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

#include "remote_auth_service.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "device_manager_util.h"
#include "hdi_wrapper.h"
#include "iam_defines.h"
#include "iam_ptr.h"
#include "remote_executor_stub.h"
#include "remote_msg_util.h"
#include "user_auth_service.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteAuthServiceImpl : public RemoteAuthService {
public:
    static RemoteAuthServiceImpl &GetInstance();
    RemoteAuthServiceImpl() = default;
    ~RemoteAuthServiceImpl() override = default;

    bool Start() override;
    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) override;

    int32_t ProcStartRemoteAuthRequest(std::string connectionName, const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply) override;
    int32_t ProcQueryExecutorInfoRequest(const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply) override;
    int32_t ProcBeginExecuteRequest(const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply) override;
    int32_t ProcEndExecuteRequest(const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply) override;

private:
    std::recursive_mutex mutex_;
    std::map<uint64_t, std::shared_ptr<RemoteExecutorStub>> scheduleId2executorStub_;
};

class RemoteAuthServiceImplConnectionListener : public ConnectionListener {
public:
    RemoteAuthServiceImplConnectionListener() = default;
    ~RemoteAuthServiceImplConnectionListener() override = default;

    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) override
    {
        IF_FALSE_LOGE_AND_RETURN(request != nullptr);
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        IAM_LOGI("connectionName: %{public}s, srcEndPoint: %{public}s", connectionName.c_str(), srcEndPoint.c_str());

        RemoteAuthServiceImpl::GetInstance().OnMessage(connectionName, srcEndPoint, request, reply);
    }

    void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus) override
    {
    }
};

RemoteAuthServiceImpl &RemoteAuthServiceImpl::GetInstance()
{
    static RemoteAuthServiceImpl remoteAuthServiceImpl;
    return remoteAuthServiceImpl;
}

bool RemoteAuthServiceImpl::Start()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    static auto callback = Common::MakeShared<RemoteAuthServiceImplConnectionListener>();
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, false);
    ResultCode registerResult = RemoteConnectionManager::GetInstance().RegisterConnectionListener(
        RemoteMsgUtil::GetRemoteServiceEndPointName(), callback);
    IF_FALSE_LOGE_AND_RETURN_VAL(registerResult == SUCCESS, false);
    IAM_LOGI("success");
    return true;
}

void RemoteAuthServiceImpl::OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    IF_FALSE_LOGE_AND_RETURN(request != nullptr);
    IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

    int32_t msgType;
    bool getMsgTypeRet = request->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType);
    IF_FALSE_LOGE_AND_RETURN(getMsgTypeRet);

    IAM_LOGI("msgType is %{public}d", msgType);
    int32_t resultCode = ResultCode::GENERAL_ERROR;
    switch (msgType) {
        case START_REMOTE_AUTH:
            resultCode = ProcStartRemoteAuthRequest(connectionName, request, reply);
            break;
        case QUERY_EXECUTOR_INFO:
            resultCode = ProcQueryExecutorInfoRequest(request, reply);
            break;
        case BEGIN_EXECUTE:
            resultCode = ProcBeginExecuteRequest(request, reply);
            break;
        case END_EXECUTE:
            resultCode = ProcEndExecuteRequest(request, reply);
            break;
        default:
            IAM_LOGE("unsupported request type: %{public}d", msgType);
            break;
    }

    bool setResultCodeRet = reply->SetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet);

    IAM_LOGI("success, msg result %{public}d", resultCode);
}

int32_t RemoteAuthServiceImpl::ProcStartRemoteAuthRequest(std::string connectionName,
    const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    auto service = UserAuthService::GetInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(service != nullptr, GENERAL_ERROR);

    return service->ProcStartRemoteAuthRequest(connectionName, request, reply);
}

int32_t RemoteAuthServiceImpl::ProcQueryExecutorInfoRequest(const std::shared_ptr<Attributes> &request,
    std::shared_ptr<Attributes> &reply)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    std::vector<int32_t> authTypes;
    bool getAuthTypesRet = request->GetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, authTypes);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTypesRet, GENERAL_ERROR);

    int32_t executorRole;
    bool getExecutorRoleRet = request->GetInt32Value(Attributes::ATTR_EXECUTOR_ROLE, executorRole);
    IF_FALSE_LOGE_AND_RETURN_VAL(getExecutorRoleRet, GENERAL_ERROR);

    std::string srcUdid;
    bool getSrcUdidRet = request->GetStringValue(Attributes::ATTR_MSG_SRC_UDID, srcUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getSrcUdidRet, GENERAL_ERROR);

    bool getQueryExecutorInfoRet = RemoteMsgUtil::GetQueryExecutorInfoReply(authTypes, executorRole, srcUdid, *reply);
    IF_FALSE_LOGE_AND_RETURN_VAL(getQueryExecutorInfoRet, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

int32_t RemoteAuthServiceImpl::ProcBeginExecuteRequest(const std::shared_ptr<Attributes> &request,
    std::shared_ptr<Attributes> &reply)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    std::shared_ptr<RemoteExecutorStub> executorStub = Common::MakeShared<RemoteExecutorStub>();
    IF_FALSE_LOGE_AND_RETURN_VAL(executorStub != nullptr, GENERAL_ERROR);

    int32_t resultCode = executorStub->ProcBeginExecuteRequest(*request);
    IF_FALSE_LOGE_AND_RETURN_VAL(resultCode == SUCCESS, GENERAL_ERROR);

    uint64_t scheduleId;
    bool getScheduleIdRet = request->GetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleIdRet, GENERAL_ERROR);

    scheduleId2executorStub_.emplace(scheduleId, executorStub);
    IAM_LOGI("success");
    return SUCCESS;
}

int32_t RemoteAuthServiceImpl::ProcEndExecuteRequest(const std::shared_ptr<Attributes> &request,
    std::shared_ptr<Attributes> &reply)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    uint64_t scheduleId;
    bool getScheduleIdRet = request->GetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleIdRet, GENERAL_ERROR);

    auto it = scheduleId2executorStub_.find(scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(it != scheduleId2executorStub_.end(), GENERAL_ERROR);
    scheduleId2executorStub_.erase(it);
    IAM_LOGI("success");
    return SUCCESS;
}

RemoteAuthService &RemoteAuthService::GetInstance()
{
    RemoteAuthServiceImpl &impl = RemoteAuthServiceImpl::GetInstance();
    return impl;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
