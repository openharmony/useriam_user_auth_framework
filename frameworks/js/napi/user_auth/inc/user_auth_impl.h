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

#ifndef FACERECOGNITION_USER_AUTH_H
#define FACERECOGNITION_USER_AUTH_H

#include "napi/native_common.h"
#include "auth_build.h"
#include "auth_common.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
typedef struct AsyncHolder {
    AsyncHolder() : data(nullptr), asyncWork(nullptr) {};
    void *data;
    napi_async_work asyncWork;
} AsyncHolder;

class UserAuthImpl {
public:
    UserAuthImpl();
    ~UserAuthImpl();
    AuthBuild authBuild;
    napi_value GetVersion(napi_env env, napi_callback_info info);
    napi_value GetAvailableStatus(napi_env env, napi_callback_info info);
    napi_value Auth(napi_env env, napi_callback_info info);
    napi_value Execute(napi_env env, napi_callback_info info);
    napi_value CancelAuth(napi_env env, napi_callback_info info);

private:

    napi_value AuthWrap(napi_env env, AuthInfo *authInfo);
    napi_value BuildAuthInfo(napi_env env, AuthInfo *authInfo);

    UserIam::UserAuth::ResultCode ParseExecuteParametersOne(napi_env env, size_t argc, napi_value *argv,
        ExecuteInfo &executeInfo);
    UserIam::UserAuth::ResultCode ParseExecuteParametersZero(napi_env env, size_t argc, napi_value *argv,
        ExecuteInfo &executeInfo);
    UserIam::UserAuth::ResultCode ParseExecuteParameters(napi_env env, size_t argc, napi_value *argv,
        ExecuteInfo &executeInfo);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // FACERECOGNITION_USER_AUTH_H
