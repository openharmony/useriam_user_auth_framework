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

#ifndef EXECUTOR_MESSENGER_SERVICE_H
#define EXECUTOR_MESSENGER_SERVICE_H

#include "context_pool.h"
#include "executor_messenger_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorMessengerService : public ExecutorMessengerStub {
public:
    static sptr<ExecutorMessengerService> GetInstance();
    int32_t SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
        const std::vector<uint8_t> &msg) override;
    int32_t Finish(uint64_t scheduleId, ExecutorRole srcRole, ResultCode resultCode,
        const std::shared_ptr<Attributes> &finalResult) override;

private:
    ExecutorMessengerService();
    ~ExecutorMessengerService() override = default;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EXECUTOR_MESSENGER_SERVICE_H