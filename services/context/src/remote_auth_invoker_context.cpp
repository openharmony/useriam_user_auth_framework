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

#include "remote_auth_invoker_context.h"

#include "device_manager_util.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "relative_timer.h"
#include "remote_connect_manager.h"
#include "thread_handler.h"
#include "user_auth_hdi.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t TIME_OUT_MS = 3 * 60 * 1000; // 3min
}
class RemoteAuthInvokerContextMessageCallback : public ConnectionListener, public NoCopyable {
public:
    explicit RemoteAuthInvokerContextMessageCallback(std::weak_ptr<BaseContext> callbackWeakBase,
        RemoteAuthInvokerContext *callback)
        : callbackWeakBase_(callbackWeakBase),
          callback_(callback),
          threadHandler_(ThreadHandler::GetSingleThreadInstance())
    {
    }

    ~RemoteAuthInvokerContextMessageCallback() = default;

    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) override
    {
        IF_FALSE_LOGE_AND_RETURN(request != nullptr);
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        IAM_LOGI("connectionName: %{public}s, srcEndPoint: %{public}s", connectionName.c_str(), srcEndPoint.c_str());

        std::shared_ptr<BaseContext> callbackSharedBase = callbackWeakBase_.lock();
        IF_FALSE_LOGE_AND_RETURN(callbackSharedBase != nullptr);

        callback_->OnMessage(connectionName, srcEndPoint, request, reply);
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
    RemoteAuthInvokerContext *callback_;
    std::shared_ptr<ThreadHandler> threadHandler_ = nullptr;
};

RemoteAuthInvokerContext::RemoteAuthInvokerContext(uint64_t contextId, AuthParamInner authParam,
    RemoteAuthInvokerContextParam param, std::shared_ptr<ContextCallback> callback)
    : BaseContext("RemoteAuthInvokerContext", contextId, callback),
      authParam_(authParam),
      connectionName_(param.connectionName),
      verifierNetworkId_(param.verifierNetworkId),
      collectorNetworkId_(param.collectorNetworkId),
      tokenId_(param.tokenId),
      collectorTokenId_(param.collectorTokenId),
      callerName_(param.callerName),
      callerType_(param.callerType),
      callback_(callback)
{
    endPointName_ = RemoteMsgUtil::GetRemoteAuthInvokerContextEndPointName();
}

RemoteAuthInvokerContext::~RemoteAuthInvokerContext()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (cancelTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(cancelTimerId_.value());
    }
    RemoteConnectionManager::GetInstance().UnregisterConnectionListener(connectionName_, endPointName_);
    RemoteConnectionManager::GetInstance().CloseConnection(connectionName_);
}

ContextType RemoteAuthInvokerContext::GetContextType() const
{
    return ContextType::REMOTE_AUTH_INVOKER_CONTEXT;
}

uint32_t RemoteAuthInvokerContext::GetTokenId() const
{
    return tokenId_;
}

void RemoteAuthInvokerContext::OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    int32_t msgType;
    IF_FALSE_LOGE_AND_RETURN(request->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType));

    int32_t resultCode = ResultCode::GENERAL_ERROR;
    switch (msgType) {
        case SEND_REMOTE_AUTH_TIP:
            resultCode = ProcAuthTipMsg(*request);
            break;
        case SEND_REMOTE_AUTH_RESULT:
            resultCode = ProcAuthResultMsg(*request);
            break;
        default:
            IAM_LOGE("invalid msgType:%{public}d", msgType);
            break;
    }

    IF_FALSE_LOGE_AND_RETURN(resultCode == ResultCode::SUCCESS);
    bool setResultCodeRet = reply->SetInt32Value(Attributes::ATTR_RESULT_CODE, ResultCode::SUCCESS);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet);
}

void RemoteAuthInvokerContext::OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    Attributes attr;
    if (connectStatus == ConnectStatus::DISCONNECTED) {
        IAM_LOGI("connection is disconnected");
        callback_->OnResult(ResultCode::GENERAL_ERROR, attr);
        return;
    } else {
        IAM_LOGI("connection is connected");
        bool sendRequestRet = SendRequest();
        if (!sendRequestRet) {
            IAM_LOGE("SendRequest failed");
            callback_->OnResult(GENERAL_ERROR, attr);
            return;
        }
        IAM_LOGI("connection is connected processed");
    }
}

void RemoteAuthInvokerContext::SetVerifierContextId(uint64_t contextId)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    verifierContextId_ = contextId;
    IAM_LOGI("verifierContextId set success");
}

bool RemoteAuthInvokerContext::OnStart()
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

    bool getUdidRet = DeviceManagerUtil::GetInstance().GetUdidByNetworkId(verifierNetworkId_, verifierUdid_);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUdidRet, false);

    endPointName_ = RemoteMsgUtil::GetRemoteAuthInvokerContextEndPointName();

    std::shared_ptr<RemoteAuthInvokerContextMessageCallback> callback =
        Common::MakeShared<RemoteAuthInvokerContextMessageCallback>(shared_from_this(), this);
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, false);

    ResultCode registerResult =
        RemoteConnectionManager::GetInstance().RegisterConnectionListener(connectionName_, endPointName_, callback);
    IF_FALSE_LOGE_AND_RETURN_VAL(registerResult == SUCCESS, false);

    ResultCode connectResult =
        RemoteConnectionManager::GetInstance().OpenConnection(connectionName_, verifierNetworkId_, GetTokenId());
    IF_FALSE_LOGE_AND_RETURN_VAL(connectResult == SUCCESS, false);

    IAM_LOGI("success");
    return true;
}

bool RemoteAuthInvokerContext::SendRequest()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    request_ = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN_VAL(request_ != nullptr, false);

    bool setMsgTypeRet = request_->SetInt32Value(Attributes::ATTR_MSG_TYPE, START_REMOTE_AUTH);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMsgTypeRet, false);

    std::vector<int32_t> authTypes = { static_cast<int32_t>(authParam_.authType) };
    bool getExecutorInfoRet = RemoteMsgUtil::GetQueryExecutorInfoReply(authTypes, COLLECTOR, verifierUdid_, *request_);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorInfoRet, false);

    bool encodeAuthParamRet = RemoteMsgUtil::EncodeAuthParam(authParam_, *request_);
    IF_FALSE_LOGE_AND_RETURN_VAL(encodeAuthParamRet, false);

    bool setTokenIdRet = request_->SetUint32Value(Attributes::ATTR_COLLECTOR_TOKEN_ID, collectorTokenId_);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTokenIdRet, false);

    bool setCallerNameRet = request_->SetStringValue(Attributes::ATTR_CALLER_NAME, callerName_);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCallerNameRet, false);

    bool setCallerTypeRet = request_->SetInt32Value(Attributes::ATTR_CALLER_TYPE, callerType_);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCallerTypeRet, false);

    bool setCollectorNetworkIdRet =
        request_->SetStringValue(Attributes::ATTR_COLLECTOR_NETWORK_ID, collectorNetworkId_);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCollectorNetworkIdRet, false);

    MsgCallback msgCallback = [weakThis = weak_from_this(), this](const std::shared_ptr<Attributes> &reply) {
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        auto sharedThis = weakThis.lock();
        IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);

        int32_t resultCode;
        bool getResultCodeRet = reply->GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
        IF_FALSE_LOGE_AND_RETURN(getResultCodeRet);

        if (resultCode != ResultCode::SUCCESS) {
            IAM_LOGE("start remote auth failed %{public}d", resultCode);
            Attributes attr;
            callback_->OnResult(resultCode, attr);
            return;
        }

        uint64_t contextId;
        bool getContextIdRet = reply->GetUint64Value(Attributes::ATTR_CONTEXT_ID, contextId);
        IF_FALSE_LOGE_AND_RETURN(getContextIdRet);

        this->SetVerifierContextId(contextId);
    };
    IF_FALSE_LOGE_AND_RETURN_VAL(request_ != nullptr, false);
    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        RemoteMsgUtil::GetRemoteServiceEndPointName(), request_, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == SUCCESS, false);

    IAM_LOGI("success");
    return true;
}

void RemoteAuthInvokerContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGE("this method is not supported");
}

bool RemoteAuthInvokerContext::OnStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("canceled");
    Attributes attr;
    callback_->OnResult(ResultCode::CANCELED, attr);
    // other module is canceled by disconnecting the connection

    IAM_LOGI("success");
    return true;
}

int32_t RemoteAuthInvokerContext::ProcAuthTipMsg(Attributes &message)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    int32_t destRole;
    bool getDestRoleRet = message.GetInt32Value(Attributes::ATTR_DEST_ROLE, destRole);
    IF_FALSE_LOGE_AND_RETURN_VAL(getDestRoleRet, ResultCode::GENERAL_ERROR);

    int32_t tipInfo;
    bool getAcquireInfoRet = message.GetInt32Value(Attributes::ATTR_TIP_INFO, tipInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAcquireInfoRet, ResultCode::GENERAL_ERROR);

    callback_->OnAcquireInfo(static_cast<ExecutorRole>(destRole), tipInfo, message.Serialize());

    IAM_LOGI("success");
    return ResultCode::SUCCESS;
}

int32_t RemoteAuthInvokerContext::ProcAuthResultMsgInner(Attributes &message, int32_t &resultCode, Attributes &attr)
{
    resultCode = GENERAL_ERROR;
    bool getResultCodeRet = message.GetInt32Value(Attributes::ATTR_RESULT, resultCode);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet, ResultCode::GENERAL_ERROR);

    std::vector<uint8_t> remoteAuthResult;
    bool getRemoteAuthResultRet = message.GetUint8ArrayValue(Attributes::ATTR_SIGNED_AUTH_RESULT, remoteAuthResult);
    if (getRemoteAuthResultRet) {
        auto hdi = HdiWrapper::GetHdiInstance();
        IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
        HdiAuthResultInfo authResultInfo;
        int32_t hdiRet = hdi->GetAuthResultFromMessage(verifierUdid_, remoteAuthResult, authResultInfo);
        IF_FALSE_LOGE_AND_RETURN_VAL(hdiRet == SUCCESS, ResultCode::GENERAL_ERROR);

        resultCode = authResultInfo.result;
        bool setLockOutDurationRet =
            attr.SetInt32Value(Attributes::ATTR_LOCKOUT_DURATION, authResultInfo.lockoutDuration);
        IF_FALSE_LOGE_AND_RETURN_VAL(setLockOutDurationRet, ResultCode::GENERAL_ERROR);
        bool setRemainAttemptsRet = attr.SetInt32Value(Attributes::ATTR_REMAIN_ATTEMPTS, authResultInfo.remainAttempts);
        IF_FALSE_LOGE_AND_RETURN_VAL(setRemainAttemptsRet, ResultCode::GENERAL_ERROR);
        bool setTokenRet = attr.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authResultInfo.token);
        IF_FALSE_LOGE_AND_RETURN_VAL(setTokenRet, ResultCode::GENERAL_ERROR);
        bool setUserId = attr.SetInt32Value(Attributes::ATTR_USER_ID, authResultInfo.userId);
        IF_FALSE_LOGE_AND_RETURN_VAL(setUserId, ResultCode::GENERAL_ERROR);
        IAM_LOGI("parsed auth result: %{public}d, lockout duration %{public}d, "
            "remain attempts %{public}d, token size %{public}zu, user id %{public}d",
            resultCode, authResultInfo.lockoutDuration, authResultInfo.remainAttempts, authResultInfo.token.size(),
            authResultInfo.userId);
    } else if (resultCode == ResultCode::SUCCESS) {
        IAM_LOGE("remote auth result is empty");
        resultCode = ResultCode::GENERAL_ERROR;
    }

    bool setResultCodeRet = attr.SetInt32Value(Attributes::ATTR_RESULT, resultCode);
    IF_FALSE_LOGE_AND_RETURN_VAL(setResultCodeRet, ResultCode::GENERAL_ERROR);

    return ResultCode::SUCCESS;
}

int32_t RemoteAuthInvokerContext::ProcAuthResultMsg(Attributes &message)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    int32_t authResultCode = GENERAL_ERROR;
    Attributes attr;

    int32_t ret = ProcAuthResultMsgInner(message, authResultCode, attr);

    callback_->OnResult(authResultCode, attr);

    IAM_LOGI("success");
    return ret;
}

void RemoteAuthInvokerContext::OnTimeOut()
{
    IAM_LOGI("timeout");
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    Attributes attr;
    callback_->OnResult(TIMEOUT, attr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS