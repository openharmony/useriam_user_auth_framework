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
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "pool.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
AuthCommand::AuthCommand(
    std::shared_ptr<Executor> executor, uint64_t scheduleId, std::shared_ptr<AuthResPool::AuthAttributes> attributes)
    : AsyncCommandBase("AUTH", scheduleId, executor),
      attributes_(attributes)
{
}

ResultCode AuthCommand::SendRequest()
{
    IAM_LOGI("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(executor_ != nullptr, ResultCode::GENERAL_ERROR);
    auto hdi = executor_->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    std::vector<uint64_t> tempalteIdList;
    std::vector<uint8_t> extraInfo;
    uint64_t templateId = 0;
    attributes_->GetUint64Value(AUTH_TEMPLATE_ID, templateId);
    uint64_t callerUid;
    attributes_->GetUint64Value(AUTH_CALLER_UID, callerUid);
    tempalteIdList.push_back(templateId);

    ResultCode ret = hdi->Authenticate(scheduleId_, callerUid, tempalteIdList, extraInfo, shared_from_this());
    IAM_LOGI("%{public}s authenticate result %{public}d", GetDescription(), ret);
    return ret;
}

void AuthCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s on result start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(executor_ != nullptr);
    auto executorMessenger = executor_->GetExecutorMessenger();
    IF_FALSE_LOGE_AND_RETURN(executorMessenger != nullptr);

    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    std::shared_ptr<AuthResPool::AuthAttributes> authAttributes = Common::MakeShared<AuthResPool::AuthAttributes>();
    IF_FALSE_LOGE_AND_RETURN(authAttributes != nullptr);
    authAttributes->SetUint32Value(AUTH_RESULT_CODE, result);
    authAttributes->SetUint8ArrayValue(AUTH_RESULT, nonConstExtraInfo);
    int32_t ret = executorMessenger->Finish(scheduleId_, ALL_IN_ONE, result, authAttributes);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGI("%{public}s call fininsh fail", GetDescription());
        return;
    }
    IAM_LOGI("%{public}s call fininsh success result=%{public}d", GetDescription(), result);
}

void AuthCommand::OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s on acquire info start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(executor_ != nullptr);
    auto executorMessenger = executor_->GetExecutorMessenger();
    IF_FALSE_LOGE_AND_RETURN(executorMessenger != nullptr);

    std::vector<uint8_t> nonConstExtraInfo(extraInfo.begin(), extraInfo.end());
    std::shared_ptr<AuthResPool::AuthMessage> msg = Common::MakeShared<AuthResPool::AuthMessage>(nonConstExtraInfo);
    IF_FALSE_LOGE_AND_RETURN(msg != nullptr);
    int32_t ret = executorMessenger->SendData(scheduleId_, transNum_, TYPE_ALL_IN_ONE, TYPE_CO_AUTH, msg);
    transNum_++;
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGI("%{public}s call SendData fail", GetDescription());
        return;
    }
    IAM_LOGI("%{public}s call SendData success acquire=%{public}d", GetDescription(), acquire);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
