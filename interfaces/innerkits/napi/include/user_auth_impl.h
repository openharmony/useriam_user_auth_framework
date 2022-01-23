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
#ifndef FACERECOGNITION_USER_AUTH_H
#define FACERECOGNITION_USER_AUTH_H

#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "auth_build.h"
#include "auth_common.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuthImpl {
public:
    UserAuthImpl();
    ~UserAuthImpl();
    AuthBuild authBuild;
    napi_value GetVersion(napi_env env, napi_callback_info info);
    napi_value GetAvailabeStatus(napi_env env, napi_callback_info info);
    napi_value GetProperty(napi_env env, napi_callback_info info);
    napi_value SetProperty(napi_env env, napi_callback_info info);
    napi_value Auth(napi_env env, napi_callback_info info);
    napi_value AuthUser(napi_env env, napi_callback_info info);
    napi_value CancelAuth(napi_env env, napi_callback_info info);

private:
    napi_value GetPropertyWrap(napi_env env, napi_callback_info info, GetPropertyInfo *getPropertyInfo);
    napi_value GetPropertyAsync(napi_env env, GetPropertyInfo *getPropertyInfo);
    napi_value GetPropertyPromise(napi_env env, GetPropertyInfo *getPropertyInfo);

    napi_value SetPropertyWrap(napi_env env, napi_callback_info info, SetPropertyInfo *setPropertyInfo);
    napi_value SetPropertyAsync(napi_env env, SetPropertyInfo *setPropertyInfo);
    napi_value SetPropertyPromise(napi_env env, SetPropertyInfo *setPropertyInfo);

    napi_value AuthWrap(napi_env env, AuthInfo *authInfo);
    napi_value AuthUserWrap(napi_env env, AuthUserInfo *userInfo);

    static void SetPropertyExecute(napi_env env, void *data);
    static void SetPropertyPromiseExecuteDone(napi_env env, napi_status status, void *data);
    static void SetPropertyAsyncExecuteDone(napi_env env, napi_status status, void *data);
    static void GetPropertyExecute(napi_env env, void *data);
    static void GetPropertyPromiseExecuteDone(napi_env env, napi_status status, void *data);
    static void GetPropertyAsyncExecuteDone(napi_env env, napi_status status, void *data);
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // FACERECOGNITION_USER_AUTH_H
