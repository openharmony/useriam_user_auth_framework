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
#ifndef MOCK_EXECUTOR_MESSENGER_SERVICE_H
#define MOCK_EXECUTOR_MESSENGER_SERVICE_H

#include <memory>

#include <gmock/gmock.h>

#include "executor_messenger_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockExecutorMessengerService final : public ExecutorMessengerStub {
public:
    MOCK_METHOD3(SendData, int32_t(uint64_t scheduleId, int32_t dstRole, const std::vector<uint8_t> &msg));
    MOCK_METHOD3(Finish, int32_t(uint64_t scheduleId, int32_t resultCode,
        const std::vector<uint8_t> &finalResult));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_EXECUTOR_MESSENGER_SERVICE_H
