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

#include "authapi_callback.h"

#include <uv.h>
#include "securec.h"

#include "auth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
AuthApiCallback::AuthApiCallback()
{
}

AuthApiCallback::~AuthApiCallback()
{
}

napi_value AuthApiCallback::BuildExecutorProperty(
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

napi_value AuthApiCallback::Uint64ToNapi(napi_env env, uint64_t value)
{
    size_t length = sizeof(value);
    napi_value out = nullptr;
    void *data = nullptr;
    napi_value arrayBuffer = nullptr;
    size_t bufferSize = length;
    NAPI_CALL(env, napi_create_arraybuffer(env, bufferSize, &data, &arrayBuffer));
    memcpy_s(data, bufferSize, reinterpret_cast<const void *>(&value), bufferSize);
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, bufferSize, arrayBuffer, 0, &out));
    return out;
}

napi_value AuthApiCallback::Uint8ArrayToNapi(napi_env env, std::vector<uint8_t> value)
{
    int size = value.size();
    HILOG_INFO("Uint8ArrayToNapi size = %{public}d", size);
    napi_value out = nullptr;
    void *data = nullptr;
    napi_value buffer = nullptr;
    NAPI_CALL(env, napi_create_arraybuffer(env, value.size(), &data, &buffer));
    if (memcpy_s(data, value.size(), value.data(), value.size()) != 0) {
        HILOG_ERROR("AuthApiCallback Uint8ArrayToNapi error");
    }
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, value.size(), buffer, 0, &out));
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

static void GetPropertyInfoCallback(uv_work_t* work, int status)
{
    HILOG_INFO("Do OnAuthAcquireInfo work");
    GetPropertyInfo *getPropertyInfo = reinterpret_cast<GetPropertyInfo *>(work->data);
    if (getPropertyInfo == nullptr) {
        HILOG_ERROR("getPropertyInfo is null");
        delete work;
        return;
    }
    napi_env env = getPropertyInfo->callBackInfo.env;
    napi_value resultData[PARAM1];
    resultData[PARAM0] = AuthApiCallback::BuildExecutorProperty(env, getPropertyInfo->getResult,
        getPropertyInfo->remainTimes, getPropertyInfo->freezingTime, getPropertyInfo->authSubType);
    if (getPropertyInfo->callBackInfo.callBack != nullptr) {
        HILOG_INFO("onExecutorPropertyInfo async");
        napi_value global = nullptr;
        napi_status napiStatus = napi_get_global(env, &global);
        if (napiStatus != napi_ok) {
            HILOG_INFO("napi_get_global faild ");
            goto EXIT;
        }
        napi_value resultValue = nullptr;
        napi_value callBack = nullptr;
        napiStatus = napi_get_reference_value(env, getPropertyInfo->callBackInfo.callBack, &callBack);
        if (napiStatus != napi_ok) {
            HILOG_INFO("napi_get_reference_value faild ");
            goto EXIT;
        }
        napiStatus = napi_call_function(env, global, callBack, PARAM1, resultData, &resultValue);
        if (napiStatus != napi_ok) {
            HILOG_INFO("napi_call_function faild ");
            goto EXIT;
        }
    } else {
        HILOG_INFO("onExecutorPropertyInfo promise");
        napi_value resultValue = resultData[PARAM0];
        napi_deferred deferred = getPropertyInfo->callBackInfo.deferred;
        napi_status napiStatus = napi_resolve_deferred(env, deferred, resultValue);
        if (napiStatus != napi_ok) {
            HILOG_INFO("napi_resolve_deferred faild ");
            goto EXIT;
        }
    }
EXIT:
    delete getPropertyInfo;
    delete work;
}

void AuthApiCallback::onExecutorPropertyInfo(const ExecutorProperty result)
{
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 1 = %{public}d", result.result);
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 2 = %{public}llu", result.authSubType);
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 3 = %{public}u", result.remainTimes);
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 4 = %{public}u", result.freezingTime);
    if (getPropertyInfo_ == nullptr) {
        HILOG_ERROR("AuthApiCallback onExecutorPropertyInfo getPropertyInfo_ is nullptr");
        return;
    }
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(getPropertyInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("loop is null");
        delete getPropertyInfo_;
        getPropertyInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("work is null");
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
    HILOG_INFO("Before GetPropertyInfoCallback");
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, GetPropertyInfoCallback);
}

void AuthApiCallback::OnAuthAcquireInfo(AcquireInfoInner *acquireInfoInner)
{
    HILOG_INFO("AuthApiCallback OnAuthAcquireInfo start");
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(authInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("loop is null");
        delete acquireInfoInner;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("work is null");
        delete acquireInfoInner;
        return;
    }
    work->data = reinterpret_cast<void *>(acquireInfoInner);
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, [] (uv_work_t *work, int status) {
        HILOG_INFO("Do OnAuthAcquireInfo work");
        AcquireInfoInner *acquireInfoInner = reinterpret_cast<AcquireInfoInner *>(work->data);
        if (acquireInfoInner == nullptr) {
            HILOG_ERROR("authInfo is null");
            delete work;
            return;
        }
        napi_env env = acquireInfoInner->env;
        napi_value returnOnAcquire = nullptr;
        napi_value callback;
        napi_status napiStatus = napi_get_reference_value(env, acquireInfoInner->onAcquireInfo, &callback);
        if (napiStatus != napi_ok) {
            HILOG_INFO("napi_get_reference_value faild ");
            delete acquireInfoInner;
            delete work;
            return;
        }
        napi_value params[PARAM3];
        napi_create_int32(env, acquireInfoInner->module, &params[PARAM0]);
        napi_create_uint32(env, acquireInfoInner->acquireInfo, &params[PARAM1]);
        napi_create_int32(env, acquireInfoInner->extraInfo, &params[PARAM2]);
        napiStatus = napi_call_function(env, acquireInfoInner->jsFunction, callback, PARAM3, params, &returnOnAcquire);
        if (napiStatus != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
        }
        delete acquireInfoInner;
        delete work;
    });
}

void AuthApiCallback::onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo)
{
    if (userInfo_ != nullptr) {
        AcquireInfoInner *acquireInfoInner = new (std::nothrow) AcquireInfoInner();
        if (acquireInfoInner == nullptr) {
            HILOG_ERROR("acquireInfoInner is null");
            return;
        }
        acquireInfoInner->env = userInfo_->callBackInfo.env;
        acquireInfoInner->onAcquireInfo = userInfo_->onAcquireInfo;
        acquireInfoInner->jsFunction = userInfo_->jsFunction;
        acquireInfoInner->module = module;
        acquireInfoInner->acquireInfo = acquireInfo;
        acquireInfoInner->extraInfo = extraInfo;
        OnAuthAcquireInfo(acquireInfoInner);
    } else {
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ is nullptr ");
    }

    if (authInfo_ != nullptr) {
        AcquireInfoInner *acquireInfoInner = new (std::nothrow) AcquireInfoInner();
        if (acquireInfoInner == nullptr) {
            HILOG_ERROR("acquireInfoInner is null");
            return;
        }
        acquireInfoInner->env = authInfo_->callBackInfo.env;
        acquireInfoInner->onAcquireInfo = authInfo_->onAcquireInfo;
        acquireInfoInner->jsFunction = authInfo_->jsFunction;
        acquireInfoInner->module = module;
        acquireInfoInner->acquireInfo = acquireInfo;
        acquireInfoInner->extraInfo = extraInfo;
        OnAuthAcquireInfo(acquireInfoInner);
    } else {
        HILOG_INFO("AuthApiCallback onAcquireInfo authInfo_ is nullptr ");
    }
    HILOG_INFO("AuthApiCallback onAcquireInfo end");
}

static void OnUserAuthResultWork(uv_work_t *work, int status)
{
    HILOG_INFO("Do OnUserAuthResult work");
    AuthUserInfo *userInfo = reinterpret_cast<AuthUserInfo *>(work->data);
    if (userInfo == nullptr) {
        HILOG_ERROR("authInfo is null");
        delete work;
        return;
    }
    napi_env env = userInfo->callBackInfo.env;
    napi_value callback;
    napi_status napiStatus = napi_get_reference_value(env, userInfo->onResult, &callback);
    if (napiStatus != napi_ok) {
        HILOG_INFO("napi_get_reference_value faild ");
        delete userInfo;
        delete work;
        return;
    }
    napi_value params[PARAM2];
    napi_create_int32(env, userInfo->result, &params[PARAM0]);
    params[PARAM1] = AuthApiCallback::BuildOnResult(
        env, userInfo->remainTimes, userInfo->freezingTime, userInfo->token);
    napi_value return_val = nullptr;
    napi_call_function(env, userInfo->jsFunction, callback, PARAM2, params, &return_val);
    delete userInfo;
    delete work;
}

void AuthApiCallback::OnUserAuthResult(const int32_t result, const AuthResult extraInfo)
{
    HILOG_INFO("AuthApiCallback OnUserAuthResult start");
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(userInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("loop is null");
        delete userInfo_;
        userInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("work is null");
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
    HILOG_INFO("Do OnAuthResult work");
    AuthInfo *authInfo = reinterpret_cast<AuthInfo *>(work->data);
    if (authInfo == nullptr) {
        HILOG_ERROR("authInfo is null");
        delete work;
        return;
    }
    napi_env env = authInfo->callBackInfo.env;
    napi_value callback;
    napi_status napiStatus = napi_get_reference_value(env, authInfo->onResult, &callback);
    if (napiStatus != napi_ok) {
        HILOG_INFO("napi_get_reference_value faild ");
        delete authInfo;
        delete work;
        return;
    }
    napi_value params[PARAM2];
    napi_create_int32(env, authInfo->result, &params[PARAM0]);
    params[PARAM1] = AuthApiCallback::BuildOnResult(
        env, authInfo->remainTimes, authInfo->freezingTime, authInfo->token);
    napi_value return_val = nullptr;
    napi_call_function(env, authInfo->jsFunction, callback, PARAM2, params, &return_val);
    delete authInfo;
    delete work;
}

void AuthApiCallback::OnAuthResult(const int32_t result, const AuthResult extraInfo)
{
    HILOG_INFO("AuthApiCallback OnAuthResult start");
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(authInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("loop is null");
        delete authInfo_;
        authInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("work is null");
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

void AuthApiCallback::onResult(const int32_t result, const AuthResult extraInfo)
{
    HILOG_INFO("AuthApiCallback onResult start result = %{public}d", result);
    HILOG_INFO("AuthApiCallback onResult start token.length = %{public}d", extraInfo.token.size());
    HILOG_INFO("AuthApiCallback onResult start extraInfo.remainTimes = %{public}u", extraInfo.remainTimes);
    HILOG_INFO("AuthApiCallback onResult start extraInfo.freezingTime = %{public}u", extraInfo.freezingTime);
    if (userInfo_ != nullptr) {
        OnUserAuthResult(result, extraInfo);
    } else {
        HILOG_ERROR("AuthApiCallback onResult userInfo_ is nullptr ");
    }
    if (authInfo_ != nullptr) {
        OnAuthResult(result, extraInfo);
    } else {
        HILOG_ERROR("AuthApiCallback onResult authInfo_ is nullptr ");
    }
    HILOG_INFO("AuthApiCallback onResult end");
}

static void SetExecutorPropertyCallback(uv_work_t *work, int status)
{
    HILOG_INFO("Do SetExecutorPropertyCallback work");
    SetPropertyInfo *setPropertyInfo = reinterpret_cast<SetPropertyInfo *>(work->data);
    if (setPropertyInfo == nullptr) {
        HILOG_ERROR("authInfo is null");
        delete work;
        return;
    }
    napi_env env = setPropertyInfo->callBackInfo.env;
    napi_status napiStatus = napi_create_int32(env, setPropertyInfo->setResult, &setPropertyInfo->result);
    if (napiStatus != napi_ok) {
        HILOG_ERROR("napi_create_int32 faild");
        goto EXIT;
    }
    if (setPropertyInfo->callBackInfo.callBack != nullptr) {
        napi_value global = nullptr;
        napiStatus = napi_get_global(env, &global);
        if (napiStatus != napi_ok) {
            HILOG_ERROR("napi_get_global faild");
            goto EXIT;
        }
        napi_value resultData[PARAM1];
        resultData[PARAM0] = setPropertyInfo->result;
        setPropertyInfo->result = nullptr;
        napi_value result = nullptr;
        napi_value callBack = nullptr;
        napiStatus = napi_get_reference_value(env, setPropertyInfo->callBackInfo.callBack, &callBack);
        if (napiStatus != napi_ok) {
            HILOG_ERROR("napi_get_reference_value faild");
            goto EXIT;
        }
        napiStatus = napi_call_function(env, global, callBack, PARAM1, resultData, &result);
        if (napiStatus != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
            goto EXIT;
        }
    } else {
        napi_value result = setPropertyInfo->result;
        napi_deferred deferred = setPropertyInfo->callBackInfo.deferred;
        napiStatus = napi_resolve_deferred(env, deferred, result);
        if (napiStatus != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
            goto EXIT;
        }
    }
EXIT:
    delete setPropertyInfo;
    delete work;
}

void AuthApiCallback::onSetExecutorProperty(const int32_t result)
{
    HILOG_INFO("onSetExecutorProperty start = %{public}d", result);
    if (setPropertyInfo_ != nullptr) {
        HILOG_ERROR("setPropertyInfo is null");
        return;
    }
    uv_loop_s *loop(nullptr);
    napi_get_uv_event_loop(setPropertyInfo_->callBackInfo.env, &loop);
    if (loop == nullptr) {
        HILOG_ERROR("loop is null");
        delete setPropertyInfo_;
        setPropertyInfo_ = nullptr;
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        HILOG_ERROR("work is null");
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
