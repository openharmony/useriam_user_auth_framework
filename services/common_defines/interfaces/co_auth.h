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

#ifndef CO_AUTH_H
#define CO_AUTH_H

#include "executor_callback.h"
#include "iam_types.h"
#include "refbase.h"

#include <cstdint>
#include <iremote_broker.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuth : public IRemoteBroker {
public:
    /* Message ID */
    enum : uint32_t {
        CO_AUTH_EXECUTOR_REGISTER = 0,
    };
    virtual uint64_t ExecutorRegister(const ExecutorRegisterInfo &info, sptr<ExecutorCallback> &callback) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.CoAuth.ICoAuth");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_H