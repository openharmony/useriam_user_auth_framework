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

#ifndef CO_AUTH_CLIENT_DEFINES_H
#define CO_AUTH_CLIENT_DEFINES_H

#include <vector>

#include "attributes.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct ExecutorInfo {
    AuthType authType {0};
    ExecutorRole executorRole {0};
    uint32_t executorSensorHint {0};
    uint32_t executorMatcher {0};
    ExecutorSecureLevel esl {0};
    std::vector<uint8_t> publicKey {};
};

class AuthMessage {
public:
    static std::shared_ptr<AuthMessage> As(const std::vector<uint8_t> &msg);
};

class ExecutorMessenger {
public:
    virtual int32_t SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
        const std::shared_ptr<AuthMessage> &msg) = 0;
    virtual int32_t Finish(uint64_t scheduleId, ExecutorRole srcRole, int32_t resultCode,
        const Attributes &finalResult) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // CO_AUTH_CLIENT_DEFINES_H