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

#include "executor_callback_service.h"

#include "executor_messenger_client.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL UserIam::Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ExecutorCallbackService::ExecutorCallbackService(const std::shared_ptr<ExecutorRegisterCallback> &impl)
    : callback_(impl)
{
}

void ExecutorCallbackService::OnMessengerReady(sptr<ExecutorMessengerInterface> &messenger,
    const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    auto wrapper = Common::MakeShared<ExecutorMessengerClient>(messenger);
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return;
    }
    callback_->OnMessengerReady(wrapper, publicKey, templateIdList);
}

int32_t ExecutorCallbackService::OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
    const Attributes &command)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    return callback_->OnBeginExecute(scheduleId, publicKey, command);
}

int32_t ExecutorCallbackService::OnEndExecute(uint64_t scheduleId, const Attributes &command)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    return callback_->OnEndExecute(scheduleId, command);
}

int32_t ExecutorCallbackService::OnSetProperty(const Attributes &properties)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    return callback_->OnSetProperty(properties);
}

int32_t ExecutorCallbackService::OnGetProperty(const Attributes &condition, Attributes &values)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    return callback_->OnGetProperty(condition, values);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS