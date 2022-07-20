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

#ifndef CO_AUTH_INTERFACE_H
#define CO_AUTH_INTERFACE_H

#include <cstdint>

#include "executor_callback_interface.h"
#include "iam_common_defines.h"

#include "iremote_broker.h"
#include "refbase.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthInterface : public IRemoteBroker {
public:
    /* Message ID */
    enum : uint32_t {
        CO_AUTH_EXECUTOR_REGISTER = 0,
    };

    struct ExecutorRegisterInfo {
        AuthType authType;
        ExecutorRole executorRole;
        uint32_t executorSensorHint; // for multiple sensors index
        uint32_t executorMatcher;    // for executors matcher
        ExecutorSecureLevel esl;
        std::vector<uint8_t> publicKey;
    };

    virtual uint64_t ExecutorRegister(const ExecutorRegisterInfo &info, sptr<ExecutorCallbackInterface> &callback) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.CoAuth.ICoAuth");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_INTERFACE_H