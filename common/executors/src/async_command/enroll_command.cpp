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

#include "enroll_command.h"

#include "framework_types.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "hisysevent_adapter.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
EnrollCommand::EnrollCommand(std::weak_ptr<Executor> executor, uint64_t scheduleId,
    std::shared_ptr<UserIam::UserAuth::Attributes> attributes, sptr<IExecutorMessenger> executorMessenger)
    : AsyncCommandBase("ENROLL", scheduleId, executor, executorMessenger),
      attributes_(attributes),
      iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("EnrollCommand"))
{
}

ResultCode EnrollCommand::SendRequest()
{
    IAM_LOGI("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);
    auto hdi = GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    uint64_t callerUid = 0;
    bool getCallerUidRet = attributes_->GetUint64Value(UserIam::UserAuth::Attributes::ATTR_CALLER_UID, callerUid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getCallerUidRet == true, ResultCode::GENERAL_ERROR);
    std::vector<uint8_t> extraInfo;
    UserIam::UserAuth::IamHitraceHelper traceHelper("hdi Enroll");
    ResultCode ret = hdi->Enroll(scheduleId_, callerUid, extraInfo, shared_from_this());
    IAM_LOGI("%{public}s enroll result %{public}d", GetDescription(), ret);
    return ret;
}

void EnrollCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s on result start", GetDescription());
    ReportTemplateChange(GetExecutorType(), OperationType::ADD_CREDENTIAL, "User Operation");
    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    auto authAttributes = Common::MakeShared<UserIam::UserAuth::Attributes>();
    IF_FALSE_LOGE_AND_RETURN(authAttributes != nullptr);
    bool setResultCodeRet = authAttributes->SetUint32Value(UserIam::UserAuth::Attributes::ATTR_RESULT_CODE, result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setAuthResultRet =
        authAttributes->SetUint8ArrayValue(UserIam::UserAuth::Attributes::ATTR_RESULT, nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(setAuthResultRet == true);
    iamHitraceHelper_ = nullptr;
    int32_t ret = MessengerFinish(scheduleId_, ALL_IN_ONE, result, authAttributes);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("%{public}s call finish fail", GetDescription());
        return;
    }
    IAM_LOGI("%{public}s call finish success result %{public}d", GetDescription(), result);
}

void EnrollCommand::OnAcquireInfoInner(int32_t acquire, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s on acquire info start", GetDescription());

    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    auto msg = Common::MakeShared<AuthMessage>(nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(msg != nullptr);
    int32_t ret = MessengerSendData(scheduleId_, transNum_, TYPE_ALL_IN_ONE, TYPE_CO_AUTH, msg);
    ++transNum_;
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("%{public}s call SendData fail", GetDescription());
        return;
    }
    IAM_LOGI("%{public}s call SendData success acquire %{public}d", GetDescription(), acquire);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
