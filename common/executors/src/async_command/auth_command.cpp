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

#include "auth_command.h"

#include "framework_types.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIam {
namespace UserAuth {
AuthCommand::AuthCommand(std::weak_ptr<Executor> executor, uint64_t scheduleId,
    const Attributes &attributes, std::shared_ptr<ExecutorMessenger> executorMessenger)
    : AsyncCommandBase("AUTH", scheduleId, executor, executorMessenger),
      attributes_(Common::MakeShared<Attributes>(attributes.Serialize())),
      iamHitraceHelper_(Common::MakeShared<IamHitraceHelper>("AuthCommand"))
{
}

ResultCode AuthCommand::SendRequest()
{
    IAM_LOGI("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);

    auto hdi = GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> extraInfo;
    bool getTemplateIdListRet =
        attributes_->GetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIdList);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTemplateIdListRet == true, ResultCode::GENERAL_ERROR);
    uint32_t tokenId = 0;
    bool getTokenIdRet = attributes_->GetUint32Value(Attributes::ATTR_ACCESS_TOKEN_ID, tokenId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTokenIdRet == true, ResultCode::GENERAL_ERROR);

    IamHitraceHelper traceHelper("hdi Authenticate");
    ResultCode ret = hdi->Authenticate(scheduleId_, tokenId, templateIdList, extraInfo, shared_from_this());
    IAM_LOGI("%{public}s authenticate result %{public}d", GetDescription(), ret);
    return ret;
}

void AuthCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s on result start", GetDescription());

    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    auto authAttributes = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN(authAttributes != nullptr);
    bool setResultCodeRet = authAttributes->SetUint32Value(Attributes::ATTR_RESULT_CODE, result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setAuthResultRet =
        authAttributes->SetUint8ArrayValue(Attributes::ATTR_RESULT, nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(setAuthResultRet == true);
    iamHitraceHelper_ = nullptr;
    int32_t ret = MessengerFinish(scheduleId_, ALL_IN_ONE, result, authAttributes);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("%{public}s call finish fail", GetDescription());
        return;
    }
    IAM_LOGI("%{public}s call finish success result %{public}d", GetDescription(), result);
}

void AuthCommand::OnAcquireInfoInner(int32_t acquire, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s on acquire info start", GetDescription());

    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    auto msg = AuthMessage::As(nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(msg != nullptr);
    int32_t ret = MessengerSendData(scheduleId_, transNum_, ALL_IN_ONE, SCHEDULER, msg);
    ++transNum_;
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("%{public}s call SendData fail", GetDescription());
        return;
    }
    IAM_LOGI("%{public}s call SendData success acquire %{public}d", GetDescription(), acquire);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
