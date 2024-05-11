/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "remote_auth_context.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "device_manager_util.h"
#include "relative_timer.h"
#include "remote_msg_util.h"
#include "resource_node_utils.h"
#include "thread_handler.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t TIME_OUT_MS = 3 * 60 * 1000; // 3min
}
class RemoteAuthContextMessageCallback : public ConnectionListener, public NoCopyable {
public:
    RemoteAuthContextMessageCallback(std::weak_ptr<BaseContext> callbackWeakBase, RemoteAuthContext *callback)
        : callbackWeakBase_(callbackWeakBase),
          callback_(callback),
          threadHandler_(ThreadHandler::GetSingleThreadInstance())
    {
    }

    ~RemoteAuthContextMessageCallback() = default;

    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) override
    {
        IF_FALSE_LOGE_AND_RETURN(request != nullptr);
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        IAM_LOGI("connectionName: %{public}s, srcEndPoint: %{public}s", connectionName.c_str(), srcEndPoint.c_str());
    }

    void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus) override
    {
        IAM_LOGI("connectionName: %{public}s, connectStatus %{public}d", connectionName.c_str(), connectStatus);

        IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
        threadHandler_->PostTask(
            [connectionName, connectStatus, callbackWeakBase = callbackWeakBase_, callback = callback_, this]() {
                IAM_LOGI("OnConnectStatus process begin");
                auto callbackSharedBase = callbackWeakBase.lock();
                IF_FALSE_LOGE_AND_RETURN(callbackSharedBase != nullptr);

                IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
                callback->OnConnectStatus(connectionName, connectStatus);
                IAM_LOGI("OnConnectStatus process success");
            });
        IAM_LOGI("task posted");
    }

private:
    std::weak_ptr<BaseContext> callbackWeakBase_;
    RemoteAuthContext *callback_ = nullptr;
    std::shared_ptr<ThreadHandler> threadHandler_ = nullptr;
};

RemoteAuthContext::RemoteAuthContext(uint64_t contextId, std::shared_ptr<Authentication> auth,
    RemoteAuthContextParam &param, std::shared_ptr<ContextCallback> callback)
    : SimpleAuthContext("RemoteAuthContext", contextId, auth, callback),
      authType_(param.authType),
      connectionName_(param.connectionName),
      collectorNetworkId_(param.collectorNetworkId),
      executorInfoMsg_(param.executorInfoMsg)
{
    endPointName_ = RemoteMsgUtil::GetRemoteAuthContextEndPointName();
}

RemoteAuthContext::~RemoteAuthContext()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (cancelTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(cancelTimerId_.value());
    }
    RemoteConnectionManager::GetInstance().UnregisterConnectionListener(connectionName_, endPointName_);
    RemoteConnectionManager::GetInstance().CloseConnection(connectionName_);
}

ContextType RemoteAuthContext::GetContextType() const
{
    return REMOTE_AUTH_CONTEXT;
}

void RemoteAuthContext::SetExecutorInfoMsg(std::vector<uint8_t> msg)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    executorInfoMsg_ = msg;
    IAM_LOGI("executorInfoMsg_ size is %{public}zu", executorInfoMsg_.size());
}

bool RemoteAuthContext::OnStart()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    cancelTimerId_ = RelativeTimer::GetInstance().Register(
        [weakThis = weak_from_this(), this]() {
            auto sharedThis = weakThis.lock();
            IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);
            OnTimeOut();
        },
        TIME_OUT_MS);

    if (executorInfoMsg_.size() == 0) {
        IAM_LOGI("SetupConnection");
        return SetupConnection();
    }

    IAM_LOGI("StartAuth");
    return StartAuth();
}

bool RemoteAuthContext::StartAuth()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    IF_FALSE_LOGE_AND_RETURN_VAL(executorInfoMsg_.size() > 0, false);

    std::vector<ExecutorInfo> executorInfos;
    bool decodeRet = RemoteMsgUtil::DecodeQueryExecutorInfoReply(Attributes(executorInfoMsg_), executorInfos);
    IF_FALSE_LOGE_AND_RETURN_VAL(decodeRet, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(executorInfos.size() > 0, false);

    IAM_LOGE("executorRole is %{public}d", executorInfos[0].executorRole);

    remoteExecutorProxy_ = Common::MakeShared<RemoteExecutorProxy>(connectionName_, executorInfos[0]);
    IF_FALSE_LOGE_AND_RETURN_VAL(remoteExecutorProxy_ != nullptr, false);

    ResultCode startExecutorRet = remoteExecutorProxy_->Start();
    IF_FALSE_LOGE_AND_RETURN_VAL(startExecutorRet == SUCCESS, false);

    std::string collectorUdid;
    bool getCollectorUdidRet = DeviceManagerUtil::GetInstance().GetUdidByNetworkId(collectorNetworkId_, collectorUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getCollectorUdidRet, false);

    auth_->SetCollectorUdid(collectorUdid);

    IAM_LOGI("StartAuth success");
    return SimpleAuthContext::OnStart();
}

void RemoteAuthContext::StartAuthDelayed()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    IAM_LOGI("start");

    bool ret = StartAuth();
    if (!ret) {
        IAM_LOGE("StartAuth failed, latest error %{public}d", GetLatestError());
        Attributes attr;
        callback_->OnResult(GetLatestError(), attr);
        return;
    }
    IAM_LOGI("success");
}

bool RemoteAuthContext::SendQueryExecutorInfoMsg()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, false);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, QUERY_EXECUTOR_INFO);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMsgTypeRet, false);

    std::vector<int32_t> authTypes = { static_cast<int32_t>(authType_) };
    bool setAuthTypesRet = request->SetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, authTypes);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthTypesRet, false);

    bool setExecutorRoleRet = request->SetInt32Value(Attributes::ATTR_EXECUTOR_ROLE, COLLECTOR);
    IF_FALSE_LOGE_AND_RETURN_VAL(setExecutorRoleRet, false);

    std::string localUdid;
    bool getLocalUdidRet = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(localUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getLocalUdidRet, false);

    MsgCallback msgCallback = [weakThis = weak_from_this(), this](const std::shared_ptr<Attributes> &reply) {
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        auto sharedThis = weakThis.lock();
        IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);

        int32_t resultCode;
        bool getResultCodeRet = reply->GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
        IF_FALSE_LOGE_AND_RETURN(getResultCodeRet);

        if (resultCode != SUCCESS) {
            IAM_LOGE("query executor info failed");
            Attributes attr;
            callback_->OnResult(GENERAL_ERROR, attr);
            return;
        }

        SetExecutorInfoMsg(reply->Serialize());

        auto handler = ThreadHandler::GetSingleThreadInstance();
        IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
        handler->PostTask([weakThis = weak_from_this(), this]() {
            auto sharedThis = weakThis.lock();
            IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);
            StartAuthDelayed();
        });
    };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        RemoteMsgUtil::GetRemoteServiceEndPointName(), request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == SUCCESS, false);

    IAM_LOGI("success");
    return true;
}

bool RemoteAuthContext::SetupConnection()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    std::shared_ptr<RemoteAuthContextMessageCallback> callback =
        Common::MakeShared<RemoteAuthContextMessageCallback>(shared_from_this(), this);
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, false);

    ResultCode registerResult =
        RemoteConnectionManager::GetInstance().RegisterConnectionListener(connectionName_, endPointName_, callback);
    IF_FALSE_LOGE_AND_RETURN_VAL(registerResult == SUCCESS, false);

    ResultCode connectResult =
        RemoteConnectionManager::GetInstance().OpenConnection(connectionName_, collectorNetworkId_, GetTokenId());
    IF_FALSE_LOGE_AND_RETURN_VAL(connectResult == SUCCESS, false);

    IAM_LOGI("success");
    return true;
}

void RemoteAuthContext::OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    IF_FALSE_LOGE_AND_RETURN(connectionName_ == connectionName);
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    Attributes attr;
    if (connectStatus == ConnectStatus::DISCONNECTED) {
        IAM_LOGI("connection is disconnected");
        callback_->OnResult(ResultCode::GENERAL_ERROR, attr);
        return;
    } else {
        IAM_LOGI("connection is connected");
        bool sendMsgRet = SendQueryExecutorInfoMsg();
        if (!sendMsgRet) {
            IAM_LOGE("SendQueryExecutorInfoMsg failed");
            callback_->OnResult(GENERAL_ERROR, attr);
            return;
        }
        IAM_LOGI("connection is connected processed");
    }
}

void RemoteAuthContext::OnTimeOut()
{
    IAM_LOGI("timeout");
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    Attributes attr;
    callback_->OnResult(TIMEOUT, attr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
