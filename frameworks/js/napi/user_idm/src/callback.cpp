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

#include "callback.h"
#include <iremote_broker.h>
#include <uv.h>
#include "auth_common.h"
#include "useridm_hilog_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "useridentity_manager.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
namespace {
const int PARAMTWO = 2;
const int PARAMTHREE = 3;
}

napi_value GetAuthInfoRet(napi_env env, uint64_t ret)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    void* data = nullptr;
    napi_value arrayBuffer = nullptr;
    size_t bufferSize = sizeof(ret);
    NAPI_CALL(env, napi_create_arraybuffer(env, bufferSize, &data, &arrayBuffer));
    if (memcpy_s(data, bufferSize, reinterpret_cast<const void*>(&ret), bufferSize) != EOK) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "memcpy_s failed");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, bufferSize, arrayBuffer, 0, &result));
    return result;
}

static AsyncCallbackContext *CopyAsyncCallbackContext(AsyncCallbackContext *asyncCallbackContext)
{
    AsyncCallbackContext *copy = new (std::nothrow) AsyncCallbackContext();
    if (copy == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "new copy failed");
        return copy;
    }
    copy->env = asyncCallbackContext->env;
    copy->callbackInfo = asyncCallbackContext->callbackInfo;
    copy->authType = asyncCallbackContext->authType;
    copy->authSubType = asyncCallbackContext->authSubType;
    copy->credentialId = asyncCallbackContext->credentialId;
    copy->token = asyncCallbackContext->token;
    copy->idmCallOnResult = asyncCallbackContext->idmCallOnResult;
    copy->idmCallonAcquireInfo = asyncCallbackContext->idmCallonAcquireInfo;
    copy->result = asyncCallbackContext->result;
    copy->retCredentialId = asyncCallbackContext->retCredentialId;
    copy->module = asyncCallbackContext->module;
    copy->acquire = asyncCallbackContext->acquire;
    return copy;
}

IIdmCallback::IIdmCallback(AsyncCallbackContext* asyncCallbackContext)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    asyncCallbackContext_ = asyncCallbackContext;
}

static void OnResultWork(uv_work_t* work, int status)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "Do OnResultWork start");
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(work->data);
    if (asyncCallbackContext == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "asyncCallbackContext is null");
        delete work;
        return;
    }
    napi_value global;
    napi_env env = asyncCallbackContext->callbackInfo.env;
    napi_value callbackRef;
    napi_value callResult = 0;
    napi_value param[TWO_PARAMETER] = {0};
    napi_status napiStatus = napi_create_int32(env, asyncCallbackContext->result, &param[0]);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_create_int32 failed");
        goto EXIT;
    }
    param[ONE_PARAMETER] = AuthCommon::CreateObject(env, FUNC_ONRESULT, asyncCallbackContext->retCredentialId);
    if (param[ONE_PARAMETER] == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "create object failed");
        goto EXIT;
    }
    napiStatus = napi_get_reference_value(env, asyncCallbackContext->callbackInfo.onResult, &callbackRef);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_get_reference_value failed");
        goto EXIT;
    }
    napiStatus = napi_get_global(env, &global);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_get_global failed");
        goto EXIT;
    }
    napiStatus = napi_call_function(env, global, callbackRef, PARAMTWO, param, &callResult);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_call_function failed");
    }
EXIT:
    napi_delete_reference(env, asyncCallbackContext->callbackInfo.onResult);
    napi_delete_reference(env, asyncCallbackContext->callbackInfo.onAcquireInfo);
    delete asyncCallbackContext;
    delete work;
}

void IIdmCallback::OnResult(int32_t result, RequestResult extraInfo)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    if (asyncCallbackContext_ == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "asyncCallbackContext_ is nullptr");
        return;
    }
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(asyncCallbackContext_->callbackInfo.env, &loop);
    if (loop == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "loop is null");
        delete asyncCallbackContext_;
        asyncCallbackContext_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "work is null");
        delete asyncCallbackContext_;
        asyncCallbackContext_ = nullptr;
        return;
    }
    asyncCallbackContext_->result = result;
    asyncCallbackContext_->retCredentialId = extraInfo.credentialId;
    AsyncCallbackContext *copy = CopyAsyncCallbackContext(asyncCallbackContext_);
    delete asyncCallbackContext_;
    asyncCallbackContext_ = nullptr;
    if (copy == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "copy is null");
        delete work;
        return;
    }
    work->data = reinterpret_cast<void *>(copy);
    uv_queue_work(loop, work, [] (uv_work_t *work) { }, OnResultWork);
}

static void OnAcquireInfoWork(uv_work_t* work, int status)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "OnAcquireInfoWork start");
    AsyncCallbackContext *asyncCallbackContext = reinterpret_cast<AsyncCallbackContext *>(work->data);
    if (asyncCallbackContext == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "asyncCallbackContext is null");
        delete work;
        return;
    }
    napi_env env = asyncCallbackContext->callbackInfo.env;
    napi_value global;
    napi_value callbackRef;
    napi_value callResult;
    napi_value params[THREE_PARAMETER] = {0};
    napi_status napiStatus = napi_create_int32(env, asyncCallbackContext->module, &params[ZERO_PARAMETER]);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_create_int32 failed");
        goto EXIT;
    }
    napiStatus = napi_create_int32(env, asyncCallbackContext->acquire, &params[ONE_PARAMETER]);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_create_int32 failed");
        goto EXIT;
    }
    params[TWO_PARAMETER] = AuthCommon::CreateObject(env, FUNC_ONACQUIREINFO, asyncCallbackContext->retCredentialId);
    if (params[TWO_PARAMETER] == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "create object failed");
        goto EXIT;
    }
    napiStatus = napi_get_reference_value(env, asyncCallbackContext->callbackInfo.onAcquireInfo, &callbackRef);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_get_reference_value failed");
        goto EXIT;
    }
    napiStatus = napi_get_global(env, &global);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_get_global failed");
        goto EXIT;
    }
    napiStatus = napi_call_function(env, global, callbackRef, PARAMTHREE, params, &callResult);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_call_function failed");
    }
EXIT:
    delete asyncCallbackContext;
    delete work;
}

void IIdmCallback::OnAcquireInfo(int32_t module, int32_t acquire, RequestResult extraInfo)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    if (asyncCallbackContext_ == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_call_function is nullptr");
        return;
    }
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(asyncCallbackContext_->callbackInfo.env, &loop);
    if (loop == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "loop is null");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "work is null");
        return;
    }
    asyncCallbackContext_->module = module;
    asyncCallbackContext_->acquire = acquire;
    asyncCallbackContext_->retCredentialId = extraInfo.credentialId;
    AsyncCallbackContext *copy = CopyAsyncCallbackContext(asyncCallbackContext_);
    if (copy == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "copy is null");
        delete work;
        return;
    }
    work->data = reinterpret_cast<void *>(copy);
    uv_queue_work(loop, work, [] (uv_work_t *work) { }, OnAcquireInfoWork);
}

GetInfoCallbackIDM::GetInfoCallbackIDM(AsyncGetAuthInfo *asyncGetAuthInfo)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    asyncGetAuthInfo_ = asyncGetAuthInfo;
}

static napi_value CreateCredentialInfo(AsyncGetAuthInfo *asyncGetAuthInfo)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    napi_value array;
    napi_env env = asyncGetAuthInfo->env;
    NAPI_CALL(env, napi_create_array_with_length(env, asyncGetAuthInfo->info.size(), &array));
    for (uint64_t Vect = 0; Vect < asyncGetAuthInfo->info.size(); Vect ++) {
        napi_value obj;
        NAPI_CALL(env, napi_create_object(env, &obj));
        napi_value credentialId = GetAuthInfoRet(env, (asyncGetAuthInfo->info[Vect].credentialId));
        if (credentialId == nullptr) {
            USERIDM_HILOGE(MODULE_JS_NAPI, "GetAuthInfo failed");
            return nullptr;
        }
        napi_value authType;
        NAPI_CALL(env, napi_create_uint32(env,
            static_cast<int32_t>(asyncGetAuthInfo->info[Vect].authType), &authType));
        napi_value authSubType;
        NAPI_CALL(env, napi_create_uint32(env,
            static_cast<int32_t>(asyncGetAuthInfo->info[Vect].authSubType), &authSubType));
        napi_value templateId = GetAuthInfoRet(env, (asyncGetAuthInfo->info[Vect].templateId));
        if (templateId == nullptr) {
            USERIDM_HILOGE(MODULE_JS_NAPI, "GetAuthInfo failed");
            return nullptr;
        }
        NAPI_CALL(env, napi_set_named_property(env, obj, "credentialId", credentialId));
        NAPI_CALL(env, napi_set_named_property(env, obj, "authType", authType));
        NAPI_CALL(env, napi_set_named_property(env, obj, "authSubType", authSubType));
        NAPI_CALL(env, napi_set_named_property(env, obj, "templateId", templateId));
        NAPI_CALL(env, napi_set_element(env, array, Vect, obj));
    }
    return array;
}

static AsyncGetAuthInfo *CopyAsyncGetAuthInfo(AsyncGetAuthInfo *asyncGetAuthInfo)
{
    AsyncGetAuthInfo *copy = new (std::nothrow) AsyncGetAuthInfo();
    if (copy == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "new copy failed");
        return copy;
    }
    copy->env = asyncGetAuthInfo->env;
    copy->openSession = asyncGetAuthInfo->openSession;
    copy->callback = asyncGetAuthInfo->callback;
    copy->authType = asyncGetAuthInfo->authType;
    copy->deferred = asyncGetAuthInfo->deferred;
    copy->promise = asyncGetAuthInfo->promise;
    copy->info = asyncGetAuthInfo->info;
    return copy;
}

static void OnGetInfoPromiseWork(AsyncGetAuthInfo *asyncGetAuthInfo)
{
    napi_value result = CreateCredentialInfo(asyncGetAuthInfo);
    if (result == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "createCredentialInfo failed");
        return;
    }
    napi_status napiStatus = napi_resolve_deferred(asyncGetAuthInfo->env, asyncGetAuthInfo->deferred, result);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_resolve_deferred failed");
        return;
    }
}

static void OnGetInfoCallbackWork(AsyncGetAuthInfo *asyncGetAuthInfo)
{
    napi_value callback;
    napi_value global;
    napi_value callbackRet = 0;
    napi_value result = CreateCredentialInfo(asyncGetAuthInfo);
    if (result == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "createCredentialInfo failed");
        return;
    }
    napi_status napiStatus = napi_get_reference_value(asyncGetAuthInfo->env, asyncGetAuthInfo->callback, &callback);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_get_reference_value failed");
        return;
    }
    napiStatus = napi_get_global(asyncGetAuthInfo->env, &global);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_get_global failed");
        return;
    }
    napiStatus = napi_call_function(asyncGetAuthInfo->env, global, callback, ONE_PARAMETER, &result, &callbackRet);
    if (napiStatus != napi_ok) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "napi_call_function failed");
        return;
    }
}

static void OnGetInfoWork(uv_work_t* work, int status)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "OnGetInfoWork start");
    AsyncGetAuthInfo *asyncGetAuthInfo = reinterpret_cast<AsyncGetAuthInfo *>(work->data);
    if (asyncGetAuthInfo == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "asyncGetAuthInfo is null");
        delete work;
        return;
    }
    if (asyncGetAuthInfo->callback == nullptr) {
        OnGetInfoPromiseWork(asyncGetAuthInfo);
    } else {
        OnGetInfoCallbackWork(asyncGetAuthInfo);
        napi_delete_reference(asyncGetAuthInfo->env, asyncGetAuthInfo->callback);
    }
    delete asyncGetAuthInfo;
    delete work;
}

void GetInfoCallbackIDM::OnGetInfo(std::vector<CredentialInfo>& info)
{
    USERIDM_HILOGI(MODULE_JS_NAPI, "%{public}s, start", __func__);
    if (asyncGetAuthInfo_ == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "asyncGetAuthInfo_ is nullptr");
        return;
    }
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(asyncGetAuthInfo_->env, &loop);
    if (loop == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "loop is null");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "work is null");
        return;
    }
    asyncGetAuthInfo_->info = info;
    AsyncGetAuthInfo *copy = CopyAsyncGetAuthInfo(asyncGetAuthInfo_);
    if (copy == nullptr) {
        USERIDM_HILOGE(MODULE_JS_NAPI, "copy is null");
        delete work;
        return;
    }
    delete asyncGetAuthInfo_;
    asyncGetAuthInfo_ = nullptr;
    work->data = reinterpret_cast<void *>(copy);
    uv_queue_work(loop, work, [] (uv_work_t *work) { }, OnGetInfoWork);
}
} // namespace UserIDM
} // namespace UserIAM
} // namespace ohos
