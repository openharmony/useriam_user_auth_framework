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

#include "napi/native_api.h"
#include "napi/native_common.h"

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
    GetPropertyInfo *getPropertyInfo_;
    SetPropertyInfo *setPropertyInfo_;
    AuthInfo *authInfo_;
    AuthUserInfo *userInfo_;
    void onExecutorPropertyInfo(const ExecutorProperty result) override;
    void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) override;
    void onResult(const int32_t result, const AuthResult extraInfo) override;
    void onSetExecutorProperty(const int32_t result) override;

private:
    napi_value BuildExecutorProperty(
        napi_env env, int32_t result, uint32_t remainTimes, uint32_t freezingTime, uint64_t authSubType);
    napi_value Uint64ToNapi(napi_env env, uint64_t value);
    napi_value BuildOnResult(napi_env env, uint32_t remainTimes, uint32_t freezingTime, std::vector<uint8_t> token);
    napi_value Uint8ArrayToNapi(napi_env env, std::vector<uint8_t> value);
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // AUTHAPI_CALLBACK_H
