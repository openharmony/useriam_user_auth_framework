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

#include "authapi_callback.h"

#include <cinttypes>
#include <uv.h>

#include "iam_logger.h"
#include "securec.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
AuthApiCallback::AuthApiCallback(AuthInfo *authInfo)
{
    authInfo_ = authInfo;
    userInfo_ = nullptr;
    executeInfo_ = nullptr;
}

AuthApiCallback::AuthApiCallback(AuthUserInfo *userInfo)
{
    authInfo_ = nullptr;
    userInfo_ = userInfo;
    executeInfo_ = nullptr;
}

AuthApiCallback::AuthApiCallback(ExecuteInfo *executeInfo)
{
    authInfo_ = nullptr;
    userInfo_ = nullptr;
    executeInfo_ = executeInfo;
}

AuthApiCallback::~AuthApiCallback()
{
    if (authInfo_ != nullptr) {
        delete authInfo_;
    }
    if (userInfo_ != nullptr) {
        delete userInfo_;
    }
    if (executeInfo_ != nullptr) {
        delete executeInfo_;
    }
}

napi_value AuthApiCallback::Uint8ArrayToNapi(napi_env env, std::vector<uint8_t> value)
{
    size_t size = value.size();
    IAM_LOGI("size = %{public}zu", size);
    napi_value out = nullptr;
    void *data = nullptr;
    napi_value buffer = nullptr;
    NAPI_CALL(env, napi_create_arraybuffer(env, size, &data, &buffer));
    (void)memcpy_s(data, size, value.data(), value.size());
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, size, buffer, 0, &out));
    return out;
}

napi_value AuthApiCallback::BuildOnResult(
    napi_env env, uint32_t remainTimes, uint32_t freezingTime, std::vector<uint8_t> token)
{
    napi_value jsObject = nullptr;
    NAPI_CALL(env, napi_create_object(env, &jsObject));

    napi_value remainTimesValue = 0;
    NAPI_CALL(env, napi_create_uint32(env, remainTimes, &remainTimesValue));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "remainTimes", remainTimesValue));

    napi_value freezingTimeValue = 0;
    NAPI_CALL(env, napi_create_uint32(env, freezingTime, &freezingTimeValue));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "freezingTime", freezingTimeValue));

    napi_value jsToken = Uint8ArrayToNapi(env, token);
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "token", jsToken));
    return jsObject;
}

void AuthApiCallback::OnAuthAcquireInfo(AcquireInfoInner *acquireInfoInner)
{
    IAM_LOGI("start");
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(acquireInfoInner->env, &loop);
    if (loop == nullptr) {
        IAM_LOGE("loop is null");
        delete acquireInfoInner;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IAM_LOGE("work is null");
        delete acquireInfoInner;
        return;
    }
    work->data = reinterpret_cast<void *>(acquireInfoInner);
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, [] (uv_work_t *work, int status) {
        IAM_LOGI("Do OnAuthAcquireInfo work");
        AcquireInfoInner *acquireInfoInner = reinterpret_cast<AcquireInfoInner *>(work->data);
        if (acquireInfoInner == nullptr) {
            IAM_LOGE("acquireInfoInner is null");
            delete work;
            return;
        }
        napi_env env = acquireInfoInner->env;
        napi_value returnOnAcquire = nullptr;
        napi_value callback;
        napi_status napiStatus = napi_get_reference_value(env, acquireInfoInner->onAcquireInfo, &callback);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_get_reference_value failed");
            delete acquireInfoInner;
            delete work;
            return;
        }
        napi_value params[PARAM3];
        napi_create_int32(env, acquireInfoInner->module, &params[PARAM0]);
        napi_create_uint32(env, acquireInfoInner->acquireInfo, &params[PARAM1]);
        napi_create_int32(env, acquireInfoInner->extraInfo, &params[PARAM2]);
        napiStatus = napi_call_function(env, nullptr, callback, PARAM3, params, &returnOnAcquire);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_call_function failed");
        }
        delete acquireInfoInner;
        delete work;
    });
}

void AuthApiCallback::onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo)
{
    IAM_LOGI("start");
    if (userInfo_ != nullptr) {
        AcquireInfoInner *acquireInfoInner = new (std::nothrow) AcquireInfoInner();
        if (acquireInfoInner == nullptr) {
            IAM_LOGE("acquireInfoInner is null");
            return;
        }
        acquireInfoInner->env = userInfo_->callBackInfo.env;
        acquireInfoInner->onAcquireInfo = userInfo_->onAcquireInfo;
        acquireInfoInner->module = module;
        acquireInfoInner->acquireInfo = acquireInfo;
        acquireInfoInner->extraInfo = extraInfo;
        OnAuthAcquireInfo(acquireInfoInner);
    } else {
        IAM_LOGE("userInfo_ is nullptr");
    }

    if (authInfo_ != nullptr) {
        AcquireInfoInner *acquireInfoInner = new (std::nothrow) AcquireInfoInner();
        if (acquireInfoInner == nullptr) {
            IAM_LOGE("acquireInfoInner is null");
            return;
        }
        acquireInfoInner->env = authInfo_->callBackInfo.env;
        acquireInfoInner->onAcquireInfo = authInfo_->onAcquireInfo;
        acquireInfoInner->module = module;
        acquireInfoInner->acquireInfo = acquireInfo;
        acquireInfoInner->extraInfo = extraInfo;
        OnAuthAcquireInfo(acquireInfoInner);
    } else {
        IAM_LOGE("authInfo_ is nullptr");
    }
    IAM_LOGI("end");
}

static void OnUserAuthResultWork(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    AuthUserInfo *userInfo = reinterpret_cast<AuthUserInfo *>(work->data);
    if (userInfo == nullptr) {
        IAM_LOGE("userInfo is null");
        delete work;
        return;
    }
    napi_env env = userInfo->callBackInfo.env;
    napi_value callback = nullptr;
    napi_value params[PARAM2] = {nullptr};
    napi_value return_val = nullptr;
    napi_status napiStatus = napi_get_reference_value(env, userInfo->onResult, &callback);
    if (napiStatus != napi_ok) {
        IAM_LOGE("napi_get_reference_value failed");
        goto EXIT;
    }
    napi_create_int32(env, userInfo->result, &params[PARAM0]);
    params[PARAM1] = AuthApiCallback::BuildOnResult(
        env, userInfo->remainTimes, userInfo->freezingTime, userInfo->token);
    napi_call_function(env, nullptr, callback, PARAM2, params, &return_val);
EXIT:
    napi_delete_reference(env, userInfo->onResult);
    napi_delete_reference(env, userInfo->onAcquireInfo);
    delete userInfo;
    delete work;
}

void AuthApiCallback::OnUserAuthResult(const int32_t result, const AuthResult extraInfo)
{
    IAM_LOGI("start");
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(userInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        IAM_LOGE("loop is null");
        delete userInfo_;
        userInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IAM_LOGE("work is null");
        delete userInfo_;
        userInfo_ = nullptr;
        return;
    }
    userInfo_->result = result;
    userInfo_->token = extraInfo.token;
    userInfo_->freezingTime = extraInfo.freezingTime;
    userInfo_->remainTimes = extraInfo.remainTimes;
    work->data = reinterpret_cast<void *>(userInfo_);
    userInfo_ = nullptr;
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, OnUserAuthResultWork);
}

static void OnAuthResultWork(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    AuthInfo *authInfo = reinterpret_cast<AuthInfo *>(work->data);
    if (authInfo == nullptr) {
        IAM_LOGE("authInfo is null");
        delete work;
        return;
    }
    napi_env env = authInfo->callBackInfo.env;
    napi_value callback = nullptr;
    napi_value params[PARAM2] = {nullptr};
    napi_value return_val = nullptr;
    napi_status napiStatus = napi_get_reference_value(env, authInfo->onResult, &callback);
    if (napiStatus != napi_ok) {
        IAM_LOGE("napi_get_reference_value failed");
        goto EXIT;
    }
    napi_create_int32(env, authInfo->result, &params[PARAM0]);
    params[PARAM1] = AuthApiCallback::BuildOnResult(
        env, authInfo->remainTimes, authInfo->freezingTime, authInfo->token);
    napi_call_function(env, nullptr, callback, PARAM2, params, &return_val);
EXIT:
    napi_delete_reference(env, authInfo->onResult);
    napi_delete_reference(env, authInfo->onAcquireInfo);
    delete authInfo;
    delete work;
}

void AuthApiCallback::OnAuthResult(const int32_t result, const AuthResult extraInfo)
{
    IAM_LOGI("start");
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(authInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        IAM_LOGE("loop is null");
        delete authInfo_;
        authInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IAM_LOGE("work is null");
        delete authInfo_;
        authInfo_ = nullptr;
        return;
    }
    authInfo_->result = result;
    authInfo_->token = extraInfo.token;
    authInfo_->freezingTime = extraInfo.freezingTime;
    authInfo_->remainTimes = extraInfo.remainTimes;
    work->data = reinterpret_cast<void *>(authInfo_);
    authInfo_ = nullptr;
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, OnAuthResultWork);
}

static void OnExecuteResultWork(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    ExecuteInfo *executeInfo = reinterpret_cast<ExecuteInfo *>(work->data);
    if (executeInfo == nullptr) {
        IAM_LOGE("executeInfo is null");
        delete work;
        return;
    }
    napi_env env = executeInfo->env;
    napi_value result;
    if (napi_create_int32(env, executeInfo->result, &result) != napi_ok) {
        IAM_LOGE("napi_create_int32 failed");
        goto EXIT;
    }
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    if (executeInfo->isPromise) {
        if (executeInfo->result == static_cast<int32_t>(AuthenticationResult::SUCCESS)) {
            IAM_LOGI("resolve promise %{public}d",
                napi_resolve_deferred(env, executeInfo->deferred, result));
        } else {
            IAM_LOGE("reject promise %{public}d",
                napi_reject_deferred(env, executeInfo->deferred, result));
        }
    } else {
        napi_value callback;
        napi_get_reference_value(env, executeInfo->callbackRef, &callback);
        napi_value callResult = nullptr;
        IAM_LOGI("do callback %{public}d",
            napi_call_function(env, undefined, callback, 1, &result, &callResult));
    }
EXIT:
    if (!executeInfo->isPromise) {
        napi_delete_reference(env, executeInfo->callbackRef);
    }
    delete executeInfo;
    delete work;
}

void AuthApiCallback::OnExecuteResult(const int32_t result)
{
    IAM_LOGI("start");
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(executeInfo_->env, &loop);
    if (loop == nullptr) {
        IAM_LOGE("loop is null");
        delete executeInfo_;
        executeInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IAM_LOGE("work is null");
        delete executeInfo_;
        executeInfo_ = nullptr;
        return;
    }

    auto res = result2ExecuteResult.find(result);
    if (res == result2ExecuteResult.end()) {
        executeInfo_->result = static_cast<int32_t>(AuthenticationResult::GENERAL_ERROR);
        IAM_LOGE("result %{public}d not found, set execute result GENERAL_ERROR", result);
    } else {
        executeInfo_->result = static_cast<int32_t>(res->second);
        IAM_LOGI("convert result %{public}d to execute result %{public}d", result, executeInfo_->result);
    }

    work->data = reinterpret_cast<void *>(executeInfo_);
    executeInfo_ = nullptr;
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, OnExecuteResultWork);
}

void AuthApiCallback::onResult(const int32_t result, const AuthResult &extraInfo)
{
    IAM_LOGI("start result = %{public}d", result);
    if (userInfo_ != nullptr) {
        OnUserAuthResult(result, extraInfo);
    } else {
        IAM_LOGI("userInfo_ is nullptr");
    }
    if (authInfo_ != nullptr) {
        OnAuthResult(result, extraInfo);
    } else {
        IAM_LOGI("authInfo_ is nullptr");
    }
    if (executeInfo_ != nullptr) {
        OnExecuteResult(result);
    } else {
        IAM_LOGI("executeInfo_ is nullptr ");
    }
    IAM_LOGI("end");
}

GetPropApiCallback::GetPropApiCallback(GetPropertyInfo *getPropertyInfo)
{
    getPropertyInfo_ = getPropertyInfo;
}

GetPropApiCallback::~GetPropApiCallback()
{
}

static void GetPropertyInfoCallback(uv_work_t* work, int status)
{
    IAM_LOGI("start");
    GetPropertyInfo *getPropertyInfo = reinterpret_cast<GetPropertyInfo *>(work->data);
    if (getPropertyInfo == nullptr) {
        IAM_LOGE("getPropertyInfo is null");
        delete work;
        return;
    }
    napi_env env = getPropertyInfo->callBackInfo.env;
    napi_value resultData[PARAM1];
    resultData[PARAM0] = GetPropApiCallback::BuildExecutorProperty(env, getPropertyInfo->getResult,
        getPropertyInfo->remainTimes, getPropertyInfo->freezingTime, getPropertyInfo->authSubType);
    if (getPropertyInfo->callBackInfo.callBack != nullptr) {
        IAM_LOGI("onExecutorPropertyInfo async");
        napi_value global = nullptr;
        napi_status napiStatus = napi_get_global(env, &global);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_get_global failed");
            goto EXIT;
        }
        napi_value resultValue = nullptr;
        napi_value callBack = nullptr;
        napiStatus = napi_get_reference_value(env, getPropertyInfo->callBackInfo.callBack, &callBack);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_get_reference_value failed");
            goto EXIT;
        }
        napiStatus = napi_call_function(env, global, callBack, PARAM1, resultData, &resultValue);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_call_function failed");
            goto EXIT;
        }
    } else {
        IAM_LOGI("onExecutorPropertyInfo promise");
        napi_value resultValue = resultData[PARAM0];
        napi_deferred deferred = getPropertyInfo->callBackInfo.deferred;
        napi_status napiStatus = napi_resolve_deferred(env, deferred, resultValue);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_resolve_deferred failed");
            goto EXIT;
        }
    }
EXIT:
    napi_delete_reference(env, getPropertyInfo->callBackInfo.callBack);
    delete getPropertyInfo;
    delete work;
}

napi_value GetPropApiCallback::BuildExecutorProperty(
    napi_env env, int32_t result, uint32_t remainTimes, uint32_t freezingTime, uint64_t authSubType)
{
    napi_value jsObject = nullptr;
    NAPI_CALL(env, napi_create_object(env, &jsObject));

    napi_value resultValue = 0;
    NAPI_CALL(env, napi_create_int32(env, result, &resultValue));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "result", resultValue));

    napi_value remainTimesValue = 0;
    NAPI_CALL(env, napi_create_uint32(env, remainTimes, &remainTimesValue));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "remainTimes", remainTimesValue));

    napi_value freezingTimeValue = 0;
    NAPI_CALL(env, napi_create_uint32(env, freezingTime, &freezingTimeValue));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "freezingTime", freezingTimeValue));

    napi_value authSubTypeValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, static_cast<int32_t>(authSubType), &authSubTypeValue));
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "authSubType", authSubTypeValue));
    return jsObject;
}

void GetPropApiCallback::onGetProperty(const ExecutorProperty result)
{
    if (getPropertyInfo_ == nullptr) {
        IAM_LOGE("getPropertyInfo_ is nullptr");
        return;
    }
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(getPropertyInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        IAM_LOGE("loop is null");
        delete getPropertyInfo_;
        getPropertyInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IAM_LOGE("work is null");
        delete getPropertyInfo_;
        getPropertyInfo_ = nullptr;
        return;
    }
    getPropertyInfo_->getResult = result.result;
    getPropertyInfo_->authSubType = static_cast<uint64_t>(result.authSubType);
    getPropertyInfo_->remainTimes = result.remainTimes;
    getPropertyInfo_->freezingTime = result.freezingTime;
    work->data = reinterpret_cast<void *>(getPropertyInfo_);
    getPropertyInfo_ = nullptr;
    IAM_LOGI("Before GetPropertyInfoCallback");
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, GetPropertyInfoCallback);
}

SetPropApiCallback::SetPropApiCallback(SetPropertyInfo *setPropertyInfo)
{
    setPropertyInfo_ = setPropertyInfo;
}

SetPropApiCallback::~SetPropApiCallback()
{
}

static void SetExecutorPropertyCallback(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    SetPropertyInfo *setPropertyInfo = reinterpret_cast<SetPropertyInfo *>(work->data);
    if (setPropertyInfo == nullptr) {
        IAM_LOGE("setPropertyInfo is null");
        delete work;
        return;
    }
    napi_env env = setPropertyInfo->callBackInfo.env;
    napi_status napiStatus = napi_create_int32(env, setPropertyInfo->setResult, &setPropertyInfo->result);
    if (napiStatus != napi_ok) {
        IAM_LOGE("napi_create_int32 failed");
        goto EXIT;
    }
    if (setPropertyInfo->callBackInfo.callBack != nullptr) {
        napi_value global = nullptr;
        napiStatus = napi_get_global(env, &global);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_get_global failed");
            goto EXIT;
        }
        napi_value resultData[PARAM1];
        resultData[PARAM0] = setPropertyInfo->result;
        setPropertyInfo->result = nullptr;
        napi_value result = nullptr;
        napi_value callBack = nullptr;
        napiStatus = napi_get_reference_value(env, setPropertyInfo->callBackInfo.callBack, &callBack);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_get_reference_value failed");
            goto EXIT;
        }
        napiStatus = napi_call_function(env, global, callBack, PARAM1, resultData, &result);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_call_function failed");
            goto EXIT;
        }
    } else {
        napi_value result = setPropertyInfo->result;
        napi_deferred deferred = setPropertyInfo->callBackInfo.deferred;
        napiStatus = napi_resolve_deferred(env, deferred, result);
        if (napiStatus != napi_ok) {
            IAM_LOGE("napi_resolve_deferred failed");
            goto EXIT;
        }
    }
EXIT:
    napi_delete_reference(env, setPropertyInfo->callBackInfo.callBack);
    delete setPropertyInfo;
    delete work;
}

void SetPropApiCallback::onSetProperty(const int32_t result)
{
    IAM_LOGI("start = %{public}d", result);
    if (setPropertyInfo_ == nullptr) {
        IAM_LOGE("setPropertyInfo is null");
        return;
    }
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(setPropertyInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        IAM_LOGE("loop is null");
        delete setPropertyInfo_;
        setPropertyInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IAM_LOGE("work is null");
        delete setPropertyInfo_;
        setPropertyInfo_ = nullptr;
        return;
    }
    setPropertyInfo_->setResult = result;
    work->data = reinterpret_cast<void *>(setPropertyInfo_);
    setPropertyInfo_ = nullptr;
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, SetExecutorPropertyCallback);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
