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

#include "executor_callback.h"

#include "iam_logger.h"

#define LOG_LABEL Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
void ExecutorCallback::OnMessengerReady(const sptr<IExecutorMessenger> &messenger)
{
    IAM_LOGD("ExecutorCallback OnMessengerReady");
    static_cast<void>(messenger);
    return;
}

void ExecutorCallback::OnMessengerReady(const sptr<IExecutorMessenger> &messenger, std::vector<uint8_t> &publicKey,
    std::vector<uint64_t> &templateIds)
{
    IAM_LOGD("ExecutorCallback OnMessengerReady Overloading");
    static_cast<void>(messenger);
    static_cast<void>(publicKey);
    static_cast<void>(templateIds);
    return;
}
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS