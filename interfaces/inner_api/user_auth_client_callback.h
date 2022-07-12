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

#ifndef USER_AUTH_CLIENT_CALLBACK_H
#define USER_AUTH_CLIENT_CALLBACK_H

#include "attributes.h"
#include "user_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthenticationCallback {
public:
    virtual void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) = 0;
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class IdentificationCallback {
public:
    virtual void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) = 0;
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class GetPropCallback {
public:
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class SetPropCallback {
public:
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_CALLBACK_H