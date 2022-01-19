/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef AUTHAPI_CALLBACK_H
#define AUTHAPI_CALLBACK_H

#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "userauth_callback.h"
#include "userauth_info.h"

#include "auth_common.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class AuthApiCallback : public UserAuthCallback {
public:
    AuthApiCallback();
    virtual ~AuthApiCallback();
    Napi_ExecutorProperty peoperty_;
    GetPropertyInfo *getPropertyInfo_;
    SetPropertyInfo *setPropertyInfo_;
    AuthInfo *authInfo_;
    AuthUserInfo *userInfo_;
    void onExecutorPropertyInfo(const ExecutorProperty result) override;
    void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) override;
    void onResult(const int32_t result, const AuthResult extraInfo) override;
    void onSetExecutorProperty(const int32_t result) override;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // AUTHAPI_CALLBACK_H
