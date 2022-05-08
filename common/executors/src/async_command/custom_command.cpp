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

#include "custom_command.h"
#include <chrono>
#include "iam_check.h"
#include "iam_logger.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
CustomCommand::CustomCommand(
    std::shared_ptr<Executor> executor, std::shared_ptr<AuthResPool::AuthAttributes> attributes)
    : AsyncCommandBase("CUSTOM", 0, executor),
      attributes_(attributes)
{
}

ResultCode CustomCommand::SendRequest()
{
    static const size_t MAX_TEMPLATE_LIST_LEN = 1000;
    IAM_LOGI("%{public}s send request start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes_ != nullptr, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(executor_ != nullptr, ResultCode::GENERAL_ERROR);
    auto hdi = executor_->GetExecutorHdi();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);

    future_ = promise_.get_future();

    uint32_t commandId = 0;
    attributes_->GetUint32Value(AUTH_PROPERTY_MODE, commandId);
    std::vector<uint64_t> templateIdList;
    attributes_->GetUint64ArrayValue(AUTH_TEMPLATE_ID_LIST, templateIdList);
    IF_FALSE_LOGE_AND_RETURN_VAL(templateIdList.size() < MAX_TEMPLATE_LIST_LEN, ResultCode::GENERAL_ERROR);
    const uint8_t *src = static_cast<const uint8_t *>(static_cast<const void *>(&templateIdList[0]));
    std::vector<uint8_t> extraInfo(src, src + templateIdList.size() * sizeof(uint64_t) / sizeof(uint8_t));
    ResultCode ret =
        hdi->SendCommand(static_cast<UserAuth::AuthPropertyMode>(commandId), extraInfo, shared_from_this());
    IAM_LOGI("%{public}s send command result %{public}d", GetDescription(), ret);
    return ret;
}

void CustomCommand::OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s on result start", GetDescription());
    result_ = result;
    promise_.set_value();
}

void CustomCommand::OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGE("%{public}s not support", GetDescription());
}

ResultCode CustomCommand::GetResult()
{
    if (!future_.valid()) {
        IAM_LOGE("%{public}s get result before request send, error", GetDescription());
        return ResultCode::GENERAL_ERROR;
    }
    IAM_LOGI("%{public}s begin wait future", GetDescription());
    const std::chrono::seconds maxWaitTime(1);
    auto ret = future_.wait_for(maxWaitTime);
    if (ret != std::future_status::ready) {
        IAM_LOGE("%{public}s future timeout", GetDescription());
        return ResultCode::TIMEOUT;
    }
    IAM_LOGI("%{public}s get result %{public}d", GetDescription(), result_);
    return result_;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
