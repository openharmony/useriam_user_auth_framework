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

#include "executor_messenger_client.h"

#include "auth_message_impl.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL UserIam::Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ExecutorMessengerClient::ExecutorMessengerClient(const sptr<ExecutorMessengerInterface> &messenger)
    : messenger_(messenger)
{
}

int32_t ExecutorMessengerClient::SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole,
    ExecutorRole dstRole, const std::shared_ptr<AuthMessage> &msg)
{
    if (messenger_ == nullptr) {
        IAM_LOGE("messenger is nullptr");
        return GENERAL_ERROR;
    }
    std::vector<uint8_t> buffer;
    if (msg == nullptr) {
        IAM_LOGE("msg is nullptr");
        return GENERAL_ERROR;
    } else {
        buffer = AuthMessageImpl::GetMsgBuffer(msg);
    }
    return messenger_->SendData(scheduleId, transNum, srcRole, dstRole, buffer);
}

int32_t ExecutorMessengerClient::Finish(uint64_t scheduleId, ExecutorRole srcRole, int32_t resultCode,
    const Attributes &finalResult)
{
    if (messenger_ == nullptr) {
        IAM_LOGE("messenger is nullptr");
        return GENERAL_ERROR;
    }
    auto attr = Common::MakeShared<Attributes>(finalResult.Serialize());
    if (attr == nullptr) {
        IAM_LOGE("failed to create attributes");
        return GENERAL_ERROR;
    }
    return messenger_->Finish(scheduleId, srcRole, static_cast<ResultCode>(resultCode), attr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS