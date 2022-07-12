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

#ifndef CO_AUTH_CLIENT_CALLBACK_H
#define CO_AUTH_CLIENT_CALLBACK_H

#include "attributes.h"
#include "co_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorRegisterCallback {
public:
    virtual void OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIds) = 0;

    virtual int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &commandAttrs) = 0;
    virtual int32_t OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs) = 0;

    virtual int32_t OnSetProperty(const Attributes &properties) = 0;
    virtual int32_t OnGetProperty(const Attributes &conditions, Attributes &results) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // CO_AUTH_CLIENT_CALLBACK_H