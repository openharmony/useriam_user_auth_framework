/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"));
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

#ifndef MOCK_IEXECUTOR_MESSAGER_H
#define MOCK_IEXECUTOR_MESSAGER_H

#include "gmock/gmock.h"

#include "co_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::UserIam;
using namespace OHOS::UserIam::UserAuth;

class MockIExecutorMessenger : public ExecutorMessenger {
public:
    virtual ~MockIExecutorMessenger() = default;

    MOCK_METHOD5(SendData, int32_t(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
                               const std::shared_ptr<AuthMessage> &msg));
    MOCK_METHOD4(Finish,
        int32_t(uint64_t scheduleId, ExecutorRole srcRole, int32_t resultCode, const Attributes &finalResult));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_IEXECUTOR_MESSAGER_H