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

#ifndef FACERECOGNITION_AUTH_BUILD_H
#define FACERECOGNITION_AUTH_BUILD_H

#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "userauth_info.h"

#include "auth_common.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class AuthBuild {
public:
    AuthBuild();
    ~AuthBuild();
    Napi_SetPropertyRequest SetPropertyRequestBuild(napi_env env, napi_value object);
    Napi_GetPropertyRequest GetPropertyRequestBuild(napi_env env, napi_value object);
    napi_value GetNapiExecutorProperty(napi_env env, Napi_ExecutorProperty property);
    napi_value BuildAuthResult(napi_env env, Napi_AuthResult authResult);
    bool NapiTypeObject(napi_env env, napi_value value);
    bool NapiTypeBitInt(napi_env env, napi_value value);
    bool NapiTypeNumber(napi_env env, napi_value value);

    void AuthUserCallBackResult(napi_env env, AuthUserInfo *userInfo);
    void AuthUserCallBackAcquireInfo(napi_env env, AuthUserInfo *userInfo);
    void AuthCallBackAcquireInfo(napi_env env, AuthInfo *authInfo);
    void AuthCallBackResult(napi_env env, AuthInfo *authInfo);
    uint64_t GetUint8ArrayTo64(napi_env env, napi_value value);
    int NapiGetValueInt(napi_env env, napi_value value);
    napi_value Uint64ToUint8Array(napi_env env, uint64_t value);
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // FACERECOGNITION_AUTH_BUILD_H