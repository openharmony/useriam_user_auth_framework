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
typedef struct AcquireInfoInner {
    napi_env env;
    napi_ref onAcquireInfo;
    int32_t module;
    uint32_t acquireInfo;
    int32_t extraInfo;
} AcquireInfoInner;

class AuthApiCallback : public UserAuthCallback {
public:
    AuthApiCallback(AuthInfo *authInfo);
    AuthApiCallback(AuthUserInfo *userInfo);
    AuthApiCallback(ExecuteInfo *executeInfo);
    virtual ~AuthApiCallback();
    void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) override;
    void onResult(const int32_t result, const AuthResult extraInfo) override;

    static napi_value BuildOnResult(
        napi_env env, uint32_t remainTimes, uint32_t freezingTime, std::vector<uint8_t> token);
    static napi_value Uint8ArrayToNapi(napi_env env, std::vector<uint8_t> value);

private:
    void OnAuthAcquireInfo(AcquireInfoInner *acquireInfoInner);
    void OnUserAuthResult(const int32_t result, const AuthResult extraInfo);
    void OnAuthResult(const int32_t result, const AuthResult extraInfo);
    void OnExecuteResult(const int32_t result);

    AuthInfo *authInfo_;
    AuthUserInfo *userInfo_;
    ExecuteInfo *executeInfo_;
};

class GetPropApiCallback : public GetPropCallback {
public:
    GetPropApiCallback(GetPropertyInfo *getPropertyInfo);
    virtual ~GetPropApiCallback();
    void onGetProperty(const ExecutorProperty result) override;

    static napi_value BuildExecutorProperty(
        napi_env env, int32_t result, uint32_t remainTimes, uint32_t freezingTime, uint64_t authSubType);

private:
    GetPropertyInfo *getPropertyInfo_;
};

class SetPropApiCallback : public SetPropCallback {
public:
    SetPropApiCallback(SetPropertyInfo *setPropertyInfo);
    virtual ~SetPropApiCallback();
    void onSetProperty(const int32_t result) override;

private:
    SetPropertyInfo *setPropertyInfo_;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // AUTHAPI_CALLBACK_H
