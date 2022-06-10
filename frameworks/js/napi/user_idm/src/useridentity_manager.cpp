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

#include "useridentity_manager.h"
#include <securec.h>
#include <iremote_broker.h>
#include "callback.h"
#include "auth_common.h"
#include "iam_logger.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "authface_userIDM_helper.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_IDM_NAPI

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
namespace {
const size_t ARGC = 2;
}

UserIdentityManager::UserIdentityManager()
{
}

UserIdentityManager::~UserIdentityManager()
{
}

napi_value UserIdentityManager::NAPI_OpenSession(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AsyncOpenSession *asyncInfo = OCreateAsyncInfo(env);
    if (asyncInfo == nullptr) {
        return nullptr;
    }
    napi_value ret = OpenSessionWrap(env, info, asyncInfo);
    if (ret == nullptr) {
        if (asyncInfo->callback != nullptr) {
            napi_delete_reference(env, asyncInfo->callback);
        }
        if (asyncInfo != nullptr) {
            delete asyncInfo;
            asyncInfo = nullptr;
        }
    }
    return ret;
}

napi_value UserIdentityManager::OpenSessionWrap(napi_env env, napi_callback_info info, AsyncOpenSession *asyncInfo)
{
    IAM_LOGI("start");
    if (asyncInfo == nullptr) {
        return nullptr;
    }
    size_t argc = ARGS_MAX_COUNT;
    size_t callbackIndex = ZERO_PARAMETER;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc == 0) {
        NAPI_CALL(env, napi_create_promise(env, &asyncInfo->deferred, &asyncInfo->promise));
        ret = OpenSessionPromise(env, argv, argc, asyncInfo);
    } else {
        callbackIndex = argc - 1;
        NAPI_CALL(env, napi_typeof(env, argv[callbackIndex], &valuetype));
        if (valuetype == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, argv[callbackIndex], 1, &asyncInfo->callback));
            ret = OpenSessionCallback(env, argv, argc, asyncInfo);
        } else {
            NAPI_CALL(env, napi_create_promise(env, &asyncInfo->deferred, &asyncInfo->promise));
            ret = OpenSessionPromise(env, argv, argc, asyncInfo);
        }
    }
    return ret;
}

napi_value OpenSessionRet(napi_env env, AsyncOpenSession* asyncOpenSession)
{
    IAM_LOGI("start");
    if (asyncOpenSession == nullptr) {
        IAM_LOGE("asyncOpenSession is nullptr");
        return nullptr;
    }
    void* data = nullptr;
    napi_value arrayBuffer = nullptr;
    size_t bufferSize = sizeof(asyncOpenSession->openSession);
    NAPI_CALL(env, napi_create_arraybuffer(env, bufferSize, &data, &arrayBuffer));
    if (memcpy_s(data, bufferSize, reinterpret_cast<const void*>(&asyncOpenSession->openSession),
        bufferSize) != EOK) {
        IAM_LOGE("memcpy_s fail.");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, bufferSize, arrayBuffer, 0, &result));
    return result;
}


napi_value UserIdentityManager::OpenSessionCallback(napi_env env, napi_value *argv, size_t argc,
    AsyncOpenSession *asyncInfo)
{
    IAM_LOGI("start");
    if (argv == nullptr || asyncInfo == nullptr) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            AsyncOpenSession *asyncInfo = (AsyncOpenSession*)data;
            if (asyncInfo != nullptr) {
                asyncInfo->openSession = UserIDMClient::GetInstance().OpenSession();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncOpenSession *asyncInfo = (AsyncOpenSession*)data;
            if (asyncInfo != nullptr) {
                napi_value result[1] = {0};
                napi_value callback = nullptr;
                napi_value undefined = nullptr;
                napi_value callResult = nullptr;
                result[0] = OpenSessionRet(env, asyncInfo);
                if (result[0] == nullptr) {
                    IAM_LOGE("OpenSessionRet failed");
                }
                napi_get_undefined(env, &undefined);
                napi_get_reference_value(env, asyncInfo->callback, &callback);
                napi_call_function(env, undefined, callback, 1, result, &callResult);
                napi_delete_reference(env, asyncInfo->callback);
                napi_delete_async_work(env, asyncInfo->asyncWork);
                delete asyncInfo;
                asyncInfo = nullptr;
            }
        },
        reinterpret_cast<void *>(asyncInfo), &asyncInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncInfo->asyncWork));
    return result;
}

napi_value UserIdentityManager::OpenSessionPromise(napi_env env, napi_value *argv, size_t argc,
    AsyncOpenSession *asyncInfo)
{
    IAM_LOGI("start");
    if (asyncInfo == nullptr) {
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            AsyncOpenSession *asyncInfo = (AsyncOpenSession*)data;
            if (asyncInfo != nullptr) {
                asyncInfo->openSession = UserIDMClient::GetInstance().OpenSession();
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncOpenSession *asyncInfo = (AsyncOpenSession*)data;
            if (asyncInfo != nullptr) {
                napi_value retPromise = nullptr;
                retPromise = OpenSessionRet(env, asyncInfo);
                if (retPromise == nullptr) {
                    IAM_LOGE("retPromise is nullptr");
                }
                napi_resolve_deferred(asyncInfo->env, asyncInfo->deferred, retPromise);
                napi_delete_async_work(env, asyncInfo->asyncWork);
                delete asyncInfo;
                asyncInfo = nullptr;
            }
        },
        reinterpret_cast<void *>(asyncInfo), &asyncInfo->asyncWork));
    NAPI_CALL(env,  napi_queue_async_work(env, asyncInfo->asyncWork));
    return asyncInfo->promise;
}

void UserIdentityManager::AddCredentialExecute(napi_env env, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(asyncHolder->data);
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        return;
    }
    AddCredInfo addCredInfo;
    addCredInfo.authType = asyncCallbackContext->authType;
    addCredInfo.authSubType = asyncCallbackContext->authSubType;
    addCredInfo.token.assign(asyncCallbackContext->token.begin(), asyncCallbackContext->token.end());
    std::shared_ptr<IDMCallback> iidmCallback = std::make_shared<IIdmCallback>(asyncCallbackContext);
    UserIDMClient::GetInstance().AddCredential(addCredInfo, iidmCallback);
}

void UserIdentityManager::AddCredentialComplete(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
}

napi_value UserIdentityManager::BuildAddCredentialInfo(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder)
{
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(asyncHolder->data);
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        return nullptr;
    }
    if (AuthCommon::JudgeObjectType(env, info, asyncCallbackContext) != napi_ok) {
        IAM_LOGE("JudgeObjectType fail");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, AddCredentialExecute, AddCredentialComplete,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    return result;
}

napi_value UserIdentityManager::NAPI_AddCredential(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return nullptr;
    }
    AsyncCallbackContext *asyncCallbackContext = new (std::nothrow) AsyncCallbackContext();
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        delete asyncHolder;
        return nullptr;
    }
    asyncHolder->data = asyncCallbackContext;
    asyncCallbackContext->env = env;
    napi_value ret = BuildAddCredentialInfo(env, info, asyncHolder);
    if (ret == nullptr) {
        IAM_LOGE("BuildAddCredentialInfo fail");
        delete asyncCallbackContext;
        if (asyncHolder->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncHolder->asyncWork);
        }
        delete asyncHolder;
    }
    return ret;
}

void UserIdentityManager::UpdateCredentialExecute(napi_env env, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(asyncHolder->data);
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        return;
    }
    AddCredInfo addCredInfo;
    addCredInfo.authType = asyncCallbackContext->authType;
    addCredInfo.authSubType = asyncCallbackContext->authSubType;
    addCredInfo.token.assign(asyncCallbackContext->token.begin(), asyncCallbackContext->token.end());
    std::shared_ptr<IDMCallback> iidmCallback = std::make_shared<IIdmCallback>(asyncCallbackContext);
    UserIDMClient::GetInstance().UpdateCredential(addCredInfo, iidmCallback);
}

void UserIdentityManager::UpdateCredentialComplete(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
}

napi_value UserIdentityManager::BuildUpdateCredentialInfo(
    napi_env env, napi_callback_info info, AsyncHolder *asyncHolder)
{
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(asyncHolder->data);
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        return nullptr;
    }

    if (AuthCommon::JudgeObjectType(env, info, asyncCallbackContext) != napi_ok) {
        IAM_LOGE("JudgeObjectType fail");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName, UpdateCredentialExecute, UpdateCredentialComplete,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    return result;
}

napi_value UserIdentityManager::NAPI_UpdateCredential(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        IAM_LOGE("syncHolder is nullptr");
        return nullptr;
    }
    AsyncCallbackContext *asyncCallbackContext = new (std::nothrow) AsyncCallbackContext();
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        delete asyncHolder;
        return nullptr;
    }
    asyncHolder->data = asyncCallbackContext;
    asyncCallbackContext->env = env;
    napi_value ret = BuildUpdateCredentialInfo(env, info, asyncHolder);
    if (ret == nullptr) {
        IAM_LOGE("BuildUpdateCredentialInfo fail");
        delete asyncCallbackContext;
        if (asyncHolder->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncHolder->asyncWork);
        }
        delete asyncHolder;
    }
    return ret;
}

napi_value UserIdentityManager::NAPI_CloseSession(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value result = nullptr;
    int32_t retCloseSession = 0;
    UserIDMClient::GetInstance().CloseSession();
    NAPI_CALL(env, napi_create_int32(env, retCloseSession, &result));
    return result;
}

napi_value UserIdentityManager::NAPI_Cancel(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value result = nullptr;
    size_t argc = ONE_PARAMETER;
    napi_value argv[ONE_PARAMETER] = {0};
    std::unique_ptr<SyncCancelContext> syncCancelContext {new (std::nothrow) SyncCancelContext()};
    if (syncCancelContext == nullptr) {
        IAM_LOGE("syncCancelContext is nullptr");
        return result;
    }

    syncCancelContext->env = env;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    syncCancelContext->challenge = AuthCommon::JudgeArrayType(env, ZERO_PARAMETER, argv);
    if (syncCancelContext->challenge.empty() || syncCancelContext->challenge.size() < sizeof(uint64_t)) {
        IAM_LOGE("syncCancelContext->challenge is null or size is wrong!");
        return result;
    }
    uint8_t tmp[sizeof(uint64_t)];
    for (uint32_t i = 0; i < sizeof(uint64_t); i++) {
        tmp[i] = syncCancelContext->challenge[i];
    }
    uint64_t *challenge = static_cast<uint64_t *>(static_cast<void *>(tmp));
    int32_t ret = UserIDMClient::GetInstance().Cancel(*challenge);
    NAPI_CALL(env, napi_create_int32(env, ret, &result));
    return result;
}

void UserIdentityManager::DelUserExecute(napi_env env, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(asyncHolder->data);
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        return;
    }
    std::shared_ptr<IDMCallback> iidmCallback = std::make_shared<IIdmCallback>(asyncCallbackContext);
    UserIDMClient::GetInstance().DelUser(asyncCallbackContext->token, iidmCallback);
}

void UserIdentityManager::DelUserComplete(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
}

napi_value UserIdentityManager::DoDelUser(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder)
{
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(asyncHolder->data);
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    AuthCommon::JudgeDelUserType(env, info, asyncCallbackContext);
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, DelUserExecute, DelUserComplete,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    return result;
}

napi_value UserIdentityManager::NAPI_DelUser(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return nullptr;
    }
    AsyncCallbackContext *asyncCallbackContext = new (std::nothrow) AsyncCallbackContext();
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        delete asyncHolder;
        return nullptr;
    }
    asyncHolder->data = asyncCallbackContext;
    asyncCallbackContext->env = env;
    napi_value ret = DoDelUser(env, info, asyncHolder);
    if (ret == nullptr) {
        IAM_LOGE("DoDelUser fail");
        delete asyncCallbackContext;
        if (asyncHolder->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncHolder->asyncWork);
        }
        delete asyncHolder;
    }
    return ret;
}

void UserIdentityManager::DelCredExecute(napi_env env, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(asyncHolder->data);
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        return;
    }
    uint8_t tmp[sizeof(uint64_t)];
    for (uint32_t i = 0; i < sizeof(uint64_t); i++) {
        tmp[i] = asyncCallbackContext->credentialId[i];
    }
    uint64_t *tempCredentialId = static_cast<uint64_t *>(static_cast<void *>(tmp));
    std::shared_ptr<IDMCallback> iidmCallback = std::make_shared<IIdmCallback>(asyncCallbackContext);
    UserIDMClient::GetInstance().DelCred(*tempCredentialId, asyncCallbackContext->token, iidmCallback);
}

void UserIdentityManager::DelCredComplete(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
}

napi_value UserIdentityManager::DoDelCred(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder)
{
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(asyncHolder->data);
    AuthCommon::JudgeDelCredType(env, info, asyncCallbackContext);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, DelCredExecute, DelCredComplete,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    return result;
}

napi_value UserIdentityManager::NAPI_DelCred(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return nullptr;
    }
    AsyncCallbackContext *asyncCallbackContext = new (std::nothrow) AsyncCallbackContext();
    if (asyncCallbackContext == nullptr) {
        IAM_LOGE("asyncCallbackContext is nullptr");
        delete asyncHolder;
        return nullptr;
    }
    asyncHolder->data = asyncCallbackContext;
    asyncCallbackContext->env = env;
    napi_value ret = DoDelCred(env, info, asyncHolder);
    if (ret == nullptr) {
        IAM_LOGE("DoDelCred fail");
        delete asyncCallbackContext;
        if (asyncHolder->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncHolder->asyncWork);
        }
        delete asyncHolder;
    }
    return ret;
}

napi_value UserIdentityManager::NAPI_GetAuthInfo(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = new (std::nothrow) AsyncHolder();
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return nullptr;
    }
    AsyncGetAuthInfo *asyncGetAuthInfo = GCreateAsyncInfo(env);
    if (asyncGetAuthInfo == nullptr) {
        IAM_LOGE("asyncGetAuthInfo is nullptr");
        delete asyncHolder;
        return nullptr;
    }
    asyncHolder->data = asyncGetAuthInfo;
    napi_value ret = GetAuthInfoWrap(env, info, asyncHolder);
    if (ret == nullptr) {
        IAM_LOGE("GetAuthInfoWrap fail");
        if (asyncGetAuthInfo->callback != nullptr) {
            napi_delete_reference(env, asyncGetAuthInfo->callback);
        }
        delete asyncGetAuthInfo;
        if (asyncHolder->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncHolder->asyncWork);
        }
        delete asyncHolder;
    }
    return ret;
}

napi_value UserIdentityManager::GetAuthInfoWrap(napi_env env, napi_callback_info info, AsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    AsyncGetAuthInfo *asyncGetAuthInfo = reinterpret_cast<AsyncGetAuthInfo *>(asyncHolder->data);
    if (asyncGetAuthInfo == nullptr) {
        IAM_LOGE("asyncGetAuthInfo is nullptr");
        return 0;
    }
    size_t argc = ARGS_MAX_COUNT;
    size_t callbackIndex = ZERO_PARAMETER;
    napi_value argv[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc == 0) {
        NAPI_CALL(env, napi_create_promise(env, &asyncGetAuthInfo->deferred, &asyncGetAuthInfo->promise));
        ret = GetAuthInfoPromise(env, argv, argc, asyncHolder);
    } else {
        callbackIndex = argc - 1;
        NAPI_CALL(env, napi_typeof(env, argv[callbackIndex], &valueType));
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, argv[callbackIndex], 1, &asyncGetAuthInfo->callback));
            ret = GetAuthInfoCallback(env, argv, argc, asyncHolder);
        } else {
            NAPI_CALL(env, napi_create_promise(env, &asyncGetAuthInfo->deferred, &asyncGetAuthInfo->promise));
            ret = GetAuthInfoPromise(env, argv, argc, asyncHolder);
        }
    }
    return ret;
}

void UserIdentityManager::GetAuthInfoExecute(napi_env env, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    AsyncGetAuthInfo *asyncGetAuthInfo = reinterpret_cast<AsyncGetAuthInfo *>(asyncHolder->data);
    if (asyncGetAuthInfo == nullptr) {
        IAM_LOGE("asyncGetAuthInfo is nullptr");
        return;
    }
    std::shared_ptr<GetInfoCallback> getInfoCallbackIDM = std::make_shared<GetInfoCallbackIDM>(asyncGetAuthInfo);
    UserIDMClient::GetInstance().GetAuthInfo(asyncGetAuthInfo->authType, getInfoCallbackIDM);
}

void UserIdentityManager::GetAuthInfoComplete(napi_env env, napi_status status, void *data)
{
    IAM_LOGI("start");
    AsyncHolder *asyncHolder = reinterpret_cast<AsyncHolder *>(data);
    if (asyncHolder == nullptr) {
        IAM_LOGE("asyncHolder is nullptr");
        return;
    }
    napi_delete_async_work(env, asyncHolder->asyncWork);
    delete asyncHolder;
}

napi_value UserIdentityManager::GetAuthInfoCallback(napi_env env, napi_value *argv, size_t argc,
    AsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    AsyncGetAuthInfo *asyncGetAuthInfo = reinterpret_cast<AsyncGetAuthInfo *>(asyncHolder->data);
    if (asyncGetAuthInfo == nullptr) {
        IAM_LOGE("asyncGetAuthInfo is nullptr");
        return nullptr;
    }

    if (argc == ARGC) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
        if (valuetype == napi_number) {
            int32_t authType_ = 0;
            NAPI_CALL(env, napi_get_value_int32(env, argv[0], &authType_));
            asyncGetAuthInfo->authType = static_cast<AuthType>(authType_);
        } else {
            asyncGetAuthInfo->authType = static_cast<AuthType>(0);
        }
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName, GetAuthInfoExecute, GetAuthInfoComplete,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    return result;
}

napi_value UserIdentityManager::GetAuthInfoPromise(napi_env env, napi_value *argv, size_t argc,
    AsyncHolder *asyncHolder)
{
    IAM_LOGI("start");
    AsyncGetAuthInfo *asyncGetAuthInfo = reinterpret_cast<AsyncGetAuthInfo *>(asyncHolder->data);
    if (asyncGetAuthInfo == nullptr) {
        IAM_LOGE("asyncGetAuthInfo is nullptr");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (argv[0] != nullptr && valueType == napi_number) {
        int32_t jsAuthType = 0;
        NAPI_CALL(env, napi_get_value_int32(env, argv[0], &jsAuthType));
        asyncGetAuthInfo->authType = static_cast<AuthType>(jsAuthType);
    } else {
        asyncGetAuthInfo->authType = static_cast<AuthType>(0);
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        GetAuthInfoExecute, GetAuthInfoComplete,
        reinterpret_cast<void *>(asyncHolder), &asyncHolder->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncHolder->asyncWork));
    return asyncGetAuthInfo->promise;
}

static napi_value Init(napi_env env, napi_value exports)
{
    napi_value val = AuthFaceInit(env, exports);
    val = EnumExport(env, val);
    return val;
}

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = Init,
        .nm_modname = "UserIDM",
        .nm_priv = nullptr,
        .reserved = {0}
    };
    napi_module_register(&module);
}
} // namespace UserIDM
} // namespace UserIAM
} // namespace OHOS
