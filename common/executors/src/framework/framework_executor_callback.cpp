/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "framework_executor_callback.h"

#include <mutex>
#include <sstream>

#include "auth_command.h"
#include "custom_command.h"
#include "enroll_command.h"
#include "hisysevent_adapter.h"
#include "iam_check.h"
#include "iam_defines.h"
#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "identify_command.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using namespace OHOS::UserIam::UserAuth;
FrameworkExecutorCallback::FrameworkExecutorCallback(std::weak_ptr<Executor> executor) : executor_(executor)
{
    uint32_t callbackId = GenerateExecutorCallbackId();
    std::ostringstream ss;
    ss << "ExecutorCallback(Id:" << callbackId << ")";
    description_ = ss.str();
}

int32_t FrameworkExecutorCallback::OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
    const Attributes &commandAttrs)
{
    auto pk(publicKey);

    auto value = Common::MakeShared<UserIam::UserAuth::Attributes>(commandAttrs.Serialize());
    return OnBeginExecuteInner(scheduleId, pk, value);
}

ResultCode FrameworkExecutorCallback::OnBeginExecuteInner(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
    std::shared_ptr<UserIam::UserAuth::Attributes> commandAttrs)
{
    static_cast<void>(publicKey);
    IF_FALSE_LOGE_AND_RETURN_VAL(commandAttrs != nullptr, ResultCode::GENERAL_ERROR);
    uint32_t commandId = 0;
    bool getScheduleModeRet =
        commandAttrs->GetUint32Value(UserIam::UserAuth::Attributes::ATTR_SCHEDULE_MODE, commandId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleModeRet == true, ResultCode::GENERAL_ERROR);

    IAM_LOGI("%{public}s start process cmd %{public}u", GetDescription(), commandId);
    ResultCode ret = ResultCode::GENERAL_ERROR;
    switch (commandId) {
        case UserIam::UserAuth::ENROLL:
            ret = ProcessEnrollCommand(scheduleId, commandAttrs);
            break;
        case UserIam::UserAuth::AUTH:
            ret = ProcessAuthCommand(scheduleId, commandAttrs);
            break;
        case UserIam::UserAuth::IDENTIFY:
            ret = ProcessIdentifyCommand(scheduleId, commandAttrs);
            break;
        default:
            IAM_LOGE("command id %{public}u is not supported", commandId);
    }

    IAM_LOGI("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

int32_t FrameworkExecutorCallback::OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs)
{
    auto consumerAttr = Common::MakeShared<UserIam::UserAuth::Attributes>(commandAttrs.Serialize());
    return OnEndExecuteInner(scheduleId, consumerAttr);
}

ResultCode FrameworkExecutorCallback::OnEndExecuteInner(uint64_t scheduleId,
    std::shared_ptr<UserIam::UserAuth::Attributes> consumerAttr)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(consumerAttr != nullptr, ResultCode::GENERAL_ERROR);

    ResultCode ret = ProcessCancelCommand(scheduleId);
    IAM_LOGI("%{public}s cancel scheduleId %{public}s ret %{public}d", GetDescription(),
        GET_MASKED_STRING(scheduleId).c_str(), ret);
    return ret;
}

void FrameworkExecutorCallback::OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger,
    const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIds)
{
    IAM_LOGI("%{public}s start", GetDescription());
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN(hdi != nullptr);
    executorMessenger_ = messenger;
    std::vector<uint8_t> extraInfo;
    hdi->OnRegisterFinish(templateIds, publicKey, extraInfo);
}

int32_t FrameworkExecutorCallback::OnSetProperty(const Attributes &properties)
{
    auto values = Common::MakeShared<UserIam::UserAuth::Attributes>(properties.Serialize());
    return OnSetPropertyInner(values);
}

ResultCode FrameworkExecutorCallback::OnSetPropertyInner(std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(properties != nullptr, ResultCode::GENERAL_ERROR);
    uint32_t commandId = 0;
    bool getAuthPropertyModeRet =
        properties->GetUint32Value(UserIam::UserAuth::Attributes::ATTR_PROPERTY_MODE, commandId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthPropertyModeRet == true, ResultCode::GENERAL_ERROR);
    IAM_LOGI("%{public}s start process cmd %{public}u", GetDescription(), commandId);
    ResultCode ret = ResultCode::GENERAL_ERROR;
    if (commandId == PROPERTY_MODE_DEL) {
        ret = ProcessDeleteTemplateCommand(properties);
    } else {
        ret = ProcessCustomCommand(properties);
    }
    IAM_LOGI("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

int32_t FrameworkExecutorCallback::OnGetProperty(const Attributes &conditions, Attributes &results)
{
    auto cond = Common::MakeShared<UserIam::UserAuth::Attributes>(conditions.Serialize());
    auto values = Common::MakeShared<UserIam::UserAuth::Attributes>(results.Serialize());
    return OnGetPropertyInner(cond, values);
}

ResultCode FrameworkExecutorCallback::OnGetPropertyInner(std::shared_ptr<UserIam::UserAuth::Attributes> conditions,
    std::shared_ptr<UserIam::UserAuth::Attributes> values)
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(conditions != nullptr, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(values != nullptr, ResultCode::GENERAL_ERROR);
    uint32_t commandId = 0;
    bool getAuthPropertyModeRet =
        conditions->GetUint32Value(UserIam::UserAuth::Attributes::ATTR_PROPERTY_MODE, commandId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthPropertyModeRet == true, ResultCode::GENERAL_ERROR);
    if (commandId != PROPERTY_MODE_GET) {
        IAM_LOGE("command id not recognised");
        return ResultCode::GENERAL_ERROR;
    }
    ResultCode ret = ProcessGetTemplateCommand(conditions, values);
    IAM_LOGI("command id = %{public}u ret = %{public}d", commandId, ret);
    return ret;
}

ResultCode FrameworkExecutorCallback::ProcessEnrollCommand(uint64_t scheduleId,
    std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    auto command = Common::MakeShared<EnrollCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessAuthCommand(uint64_t scheduleId,
    std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    auto command = Common::MakeShared<AuthCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessIdentifyCommand(uint64_t scheduleId,
    std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    auto command = Common::MakeShared<IdentifyCommand>(executor_, scheduleId, properties, executorMessenger_);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    return command->StartProcess();
}

ResultCode FrameworkExecutorCallback::ProcessCancelCommand(uint64_t scheduleId)
{
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    return hdi->Cancel(scheduleId);
}

ResultCode FrameworkExecutorCallback::ProcessDeleteTemplateCommand(
    std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(properties != nullptr, ResultCode::GENERAL_ERROR);
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    uint64_t templateId = 0;
    bool getAuthTemplateIdRet = properties->GetUint64Value(UserIam::UserAuth::Attributes::ATTR_TEMPLATE_ID, templateId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTemplateIdRet == true, ResultCode::GENERAL_ERROR);
    std::vector<uint64_t> templateIdList;

    templateIdList.push_back(templateId);
    UserIam::UserAuth::IamHitraceHelper traceHelper("hdi Delete");
    ResultCode ret = hdi->Delete(templateIdList);
    if (ret == ResultCode::SUCCESS) {
        ReportTemplateChange(executor->GetAuthType(), UserIam::UserAuth::TRACE_DELETE_CREDENTIAL, "User Operation");
    }
    return ret;
}

ResultCode FrameworkExecutorCallback::ProcessCustomCommand(std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    auto command = Common::MakeShared<CustomCommand>(executor_, properties);
    IF_FALSE_LOGE_AND_RETURN_VAL(command != nullptr, ResultCode::GENERAL_ERROR);
    ResultCode ret = command->StartProcess();
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("start process command fail ret = %{public}d", ret);
        return ret;
    }

    return command->GetResult();
}

ResultCode FrameworkExecutorCallback::ProcessGetTemplateCommand(
    std::shared_ptr<UserIam::UserAuth::Attributes> conditions, std::shared_ptr<UserIam::UserAuth::Attributes> values)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(conditions != nullptr, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(values != nullptr, ResultCode::GENERAL_ERROR);
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("executor has been released, process failed");
        return ResultCode::GENERAL_ERROR;
    }
    auto hdi = executor->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
    uint64_t templateId = 0;
    bool getAuthTemplateIdRet = conditions->GetUint64Value(UserIam::UserAuth::Attributes::ATTR_TEMPLATE_ID, templateId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTemplateIdRet == true, ResultCode::GENERAL_ERROR);
    TemplateInfo templateInfo = {};
    ResultCode ret = hdi->GetTemplateInfo(templateId, templateInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == SUCCESS, ret);
    uint64_t subType = 0;
    Common::UnpackUint64(templateInfo.extraInfo, 0, subType);
    bool setAuthSubTypeRet = values->SetUint64Value(UserIam::UserAuth::Attributes::ATTR_PIN_SUB_TYPE, subType);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthSubTypeRet == true, ResultCode::GENERAL_ERROR);
    bool setAuthRemainTimeRet =
        values->SetUint32Value(UserIam::UserAuth::Attributes::ATTR_FREEZING_TIME, templateInfo.freezingTime);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthRemainTimeRet == true, ResultCode::GENERAL_ERROR);
    bool setAuthRemainCountRet =
        values->SetUint32Value(UserIam::UserAuth::Attributes::ATTR_REMAIN_TIMES, templateInfo.remainTimes);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthRemainCountRet == true, ResultCode::GENERAL_ERROR);
    return ResultCode::SUCCESS;
}

uint32_t FrameworkExecutorCallback::GenerateExecutorCallbackId()
{
    static std::mutex mutex;
    static uint32_t callbackId = 0;
    std::lock_guard<std::mutex> guard(mutex);
    // callbackId is only used in log, uint32 overflow or duplicate is ok
    ++callbackId;
    return callbackId;
}

const char *FrameworkExecutorCallback::GetDescription()
{
    return description_.c_str();
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
