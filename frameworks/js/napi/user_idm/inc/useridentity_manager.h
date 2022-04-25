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

#ifndef USERIDENTITY_MANAGER_H
#define USERIDENTITY_MANAGER_H

#include <vector>
#include <string>
#include <iostream>
#include <securec.h>
#include "useridm_client.h"
#include "useridm_callback.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
constexpr size_t ZERO_PARAMETER = 0;
constexpr size_t ONE_PARAMETER = 1;
constexpr size_t TWO_PARAMETER = 2;
constexpr size_t THREE_PARAMETER = 3;
constexpr size_t ARGS_MAX_COUNT = 10;
constexpr size_t RESULT = 0;
constexpr char PROPERTY_KEY_NAME[] = "credType";
constexpr char PROPERTY_KEY_ID[] = "credSubType";
constexpr char PROPERTY_KEY_EVENT[] = "token";
constexpr char FUNC_ONRESULT[] = "OnResult";
constexpr char FUNC_ONACQUIREINFO[] = "OnAcquireInfo";

typedef struct AsyncOpenSession {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_value promise;
    napi_ref callback;
    uint64_t openSession;
} AsyncOpenSession;

typedef struct AsyncGetAuthInfo {
    napi_env env;
    uint64_t openSession;
    napi_ref callback;
    AuthType authType;
    napi_deferred deferred;
    napi_value promise;
    std::vector<CredentialInfo> info;
} AsyncGetAuthInfo;

typedef struct CallbackInfo {
    napi_env env;
    napi_ref onResult;
    napi_ref onAcquireInfo;
} CallbackInfo;

typedef struct AsyncCallbackContext {
    napi_env env;
    CallbackInfo callbackInfo;
    AuthType authType;
    AuthSubType authSubType;
    std::vector<uint8_t> credentialId;
    std::vector<uint8_t> token;
    napi_value idmCallOnResult;
    napi_value idmCallonAcquireInfo;
    int32_t result;
    uint64_t retCredentialId;
    int32_t module;
    int32_t acquire;
} AsyncCallbackContext;

typedef struct SyncCancelContext {
    napi_env env;
    std::vector<uint8_t> challenge;
} SyncCancelContext;

typedef struct AsyncHolder {
    AsyncHolder() : data(nullptr), asyncWork(nullptr) {};
    void *data;
    napi_async_work asyncWork;
} AsyncHolder;

class UserIdentityManager {
public:
    UserIdentityManager();
    ~UserIdentityManager();
    napi_value NAPI_OpenSession(napi_env env, napi_callback_info info);
    napi_value NAPI_AddCredential(napi_env env, napi_callback_info info);
    napi_value NAPI_UpdateCredential(napi_env env, napi_callback_info info);
    napi_value NAPI_CloseSession(napi_env env, napi_callback_info info);
    napi_value NAPI_Cancel(napi_env env, napi_callback_info info);
    napi_value NAPI_DelUser(napi_env env, napi_callback_info info);
    napi_value NAPI_DelCred(napi_env env, napi_callback_info info);
    napi_value NAPI_GetAuthInfo(napi_env env, napi_callback_info info);

private:
    napi_value OpenSessionWrap(napi_env env, napi_callback_info info, AsyncOpenSession *asyncInfo);
    napi_value OpenSessionCallback(napi_env env, napi_value *args, size_t argcAsync, AsyncOpenSession *asyncInfo);
    napi_value OpenSessionPromise(napi_env env, napi_value *args, size_t argcAsync, AsyncOpenSession *asyncInfo);

    napi_value GetAuthInfoWrap(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder);
    napi_value GetAuthInfoCallback(napi_env env, napi_value *args, size_t argcAsync, AsyncHolder *asyncHolder);
    napi_value GetAuthInfoPromise(napi_env env, napi_value *args, size_t argcAsync, AsyncHolder *asyncHolder);

    napi_value BuildAddCredentialInfo(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder);
    napi_value BuildUpdateCredentialInfo(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder);
    napi_value DoDelUser(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder);
    napi_value DoDelCred(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder);

    static void GetAuthInfoExecute(napi_env env, void *data);
    static void GetAuthInfoComplete(napi_env env, napi_status status, void *data);
    static void AddCredentialExecute(napi_env env, void *data);
    static void AddCredentialComplete(napi_env env, napi_status status, void *data);
    static void UpdateCredentialExecute(napi_env env, void *data);
    static void UpdateCredentialComplete(napi_env env, napi_status status, void *data);
    static void DelUserExecute(napi_env env, void *data);
    static void DelUserComplete(napi_env env, napi_status status, void *data);
    static void DelCredExecute(napi_env env, void *data);
    static void DelCredComplete(napi_env env, napi_status status, void *data);
};

AsyncGetAuthInfo *GCreateAsyncInfo(napi_env env);
AsyncOpenSession *OCreateAsyncInfo(napi_env env);
napi_value OpenSessionRet(napi_env env, AsyncOpenSession *asyncOpenSession);
} // namespace UserIDM
} // namespace UserIAM
} // namespace OHOS

#endif // USERIDENTITY_MANAGER_H
