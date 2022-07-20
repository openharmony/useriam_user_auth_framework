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

#ifndef EXECUTOR_CALLBACK_SERVICE_H
#define EXECUTOR_CALLBACK_SERVICE_H

#include "executor_callback_stub.h"

#include "co_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorCallbackService : public ExecutorCallbackStub {
public:
    explicit ExecutorCallbackService(const std::shared_ptr<ExecutorRegisterCallback> &impl);
    ~ExecutorCallbackService() override = default;
    void OnMessengerReady(sptr<ExecutorMessengerInterface> &messenger, const std::vector<uint8_t> &publicKey,
        const std::vector<uint64_t> &templateIdList) override;
    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command) override;
    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &command) override;
    int32_t OnSetProperty(const Attributes &properties) override;
    int32_t OnGetProperty(const Attributes &condition, Attributes &values) override;

private:
    std::shared_ptr<ExecutorRegisterCallback> callback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EXECUTOR_CALLBACK_SERVICE_H