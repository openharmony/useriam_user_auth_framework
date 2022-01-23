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

    napi_value jsType = Uint64ToNapi(env, authSubType);
    NAPI_CALL(env, napi_set_named_property(env, jsObject, "authSubType", jsType));
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

void AuthApiCallback::onExecutorPropertyInfo(const ExecutorProperty result)
{
    napi_status status;
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 1 = %{public}d", result.result);
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 2 = %{public}llu", result.authSubType);
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 3 = %{public}u", result.remainTimes);
    HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 4 = %{public}u", result.freezingTime);
    if (getPropertyInfo_ != nullptr) {
        napi_env env = getPropertyInfo_->callBackInfo.env;
        HILOG_INFO("AuthApiCallback onExecutorPropertyInfo 5 ");
        napi_value resultData[PARAM1];
        resultData[PARAM0] = BuildExecutorProperty(
            env, result.result, result.remainTimes, result.freezingTime, static_cast<uint64_t>(result.authSubType));
        if (getPropertyInfo_->callBackInfo.callBack != nullptr) {
            HILOG_INFO("AuthApiCallback onExecutorPropertyInfo async 6");
            napi_value global = nullptr;
            status = napi_get_global(env, &global);
            if (status != napi_ok) {
                HILOG_INFO("napi_get_global faild ");
            }
            napi_value resultValue = nullptr;
            napi_value callBack = nullptr;
            status = napi_get_reference_value(env, getPropertyInfo_->callBackInfo.callBack, &callBack);
            if (status != napi_ok) {
                HILOG_INFO("napi_get_reference_value faild ");
            }
            status = napi_call_function(env, global, callBack, PARAM1, resultData, &resultValue);
            if (status != napi_ok) {
                HILOG_INFO("napi_call_function faild ");
            }
        } else {
            HILOG_INFO("AuthApiCallback onExecutorPropertyInfo promise 6");
            napi_value resultValue = resultData[PARAM0];
            napi_deferred deferred = getPropertyInfo_->callBackInfo.deferred;
            status = napi_resolve_deferred(env, deferred, resultValue);
            if (status != napi_ok) {
                HILOG_INFO("napi_resolve_deferred faild ");
            }
        }
        delete getPropertyInfo_;
        getPropertyInfo_ = nullptr;
    } else {
        HILOG_ERROR("AuthApiCallback onExecutorPropertyInfo getPropertyInfo_ is nullptr");
    }
}

void AuthApiCallback::onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo)
{
    napi_status status;
    napi_value callback;
    napi_value params[PARAM3];
    if (userInfo_ != nullptr) {
        napi_env env = userInfo_->callBackInfo.env;
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ start 1");
        napi_value returnOnAcquire = nullptr;
        status = napi_get_reference_value(env, userInfo_->onAcquireInfo, &callback);
        if (status != napi_ok) {
            HILOG_INFO("napi_get_reference_value faild ");
        }
        napi_create_int32(env, module, &params[PARAM0]);
        napi_create_uint32(env, acquireInfo, &params[PARAM1]);
        napi_create_int32(env, extraInfo, &params[PARAM2]);
        status = napi_call_function(env, userInfo_->jsFunction, callback, PARAM3, params, &returnOnAcquire);
        if (status != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
        }
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ start 4");
    } else {
        HILOG_INFO("AuthApiCallback onAcquireInfo userInfo_ is nullptr ");
    }

    if (authInfo_ != nullptr) {
        napi_env env = authInfo_->callBackInfo.env;
        napi_value returnOnAcquire = nullptr;
        status = napi_get_reference_value(env, authInfo_->onAcquireInfo, &callback);
        if (status != napi_ok) {
            HILOG_INFO("napi_get_reference_value faild ");
        }
        napi_create_int32(env, module, &params[PARAM0]);
        napi_create_uint32(env, acquireInfo, &params[PARAM1]);
        napi_create_int32(env, extraInfo, &params[PARAM2]);
        status = napi_call_function(env, authInfo_->jsFunction, callback, PARAM3, params, &returnOnAcquire);
        if (status != napi_ok) {
            HILOG_ERROR("napi_call_function faild");
        }
        HILOG_INFO("AuthApiCallback onAcquireInfo authInfo_ start 4");
    } else {
        HILOG_INFO("AuthApiCallback onAcquireInfo authInfo_ is nullptr ");
    }
    HILOG_INFO("AuthApiCallback onAcquireInfo end");
}

void AuthApiCallback::onResult(const int32_t result, const AuthResult extraInfo)
{
    HILOG_INFO("AuthApiCallback onResult start result = %{public}d", result);
    HILOG_INFO("AuthApiCallback onResult start token.length = %{public}d", extraInfo.token.size());
    HILOG_INFO("AuthApiCallback onResult start extraInfo.remainTimes = %{public}u", extraInfo.remainTimes);
    HILOG_INFO("AuthApiCallback onResult start extraInfo.freezingTime = %{public}u", extraInfo.freezingTime);
    napi_status status;
    napi_value callback;
    if (userInfo_ != nullptr) {
        napi_env env = userInfo_->callBackInfo.env;
        status = napi_get_reference_value(env, userInfo_->onResult, &callback);
        if (status != napi_ok) {
            HILOG_INFO("napi_get_reference_value faild ");
        }
        napi_value params[PARAM2];
        napi_create_int32(env, result, &params[PARAM0]);
        params[PARAM1] = BuildOnResult(env, extraInfo.remainTimes, extraInfo.freezingTime, extraInfo.token);
        napi_value return_val = nullptr;
        HILOG_INFO("AuthApiCallback onResult userInfo_ 5");
        napi_call_function(env, userInfo_->jsFunction, callback, PARAM2, params, &return_val);
        delete userInfo_;
        userInfo_ = nullptr;
    } else {
        HILOG_ERROR("AuthApiCallback onResult userInfo_ is nullptr ");
    }
    if (authInfo_ != nullptr) {
        HILOG_INFO("AuthApiCallback onResult authInfo_ 1");
        napi_env env = authInfo_->callBackInfo.env;
        HILOG_INFO("AuthApiCallback onResult authInfo_ 2");
        status = napi_get_reference_value(authInfo_->callBackInfo.env, authInfo_->onResult, &callback);
        if (status != napi_ok) {
            HILOG_INFO("napi_get_reference_value faild ");
        }
        napi_value params[PARAM2];
        napi_create_int32(env, result, &params[PARAM0]);
        params[PARAM1] = BuildOnResult(env, extraInfo.remainTimes, extraInfo.freezingTime, extraInfo.token);
        napi_value return_val = nullptr;
        HILOG_INFO("AuthApiCallback onResult userInfo_ 5");
        napi_call_function(env, authInfo_->jsFunction, callback, PARAM2, params, &return_val);
        HILOG_INFO("AuthApiCallback onResult authInfo_ 6");
        delete authInfo_;
        authInfo_ = nullptr;
    } else {
        HILOG_ERROR("AuthApiCallback onResult authInfo_ is nullptr ");
    }
    HILOG_INFO("AuthApiCallback onResult end");
}

void AuthApiCallback::onSetExecutorProperty(const int32_t result)
{
    HILOG_INFO("onSetExecutorProperty start = %{public}d", result);
    napi_status status;
    if (setPropertyInfo_ != nullptr) {
        napi_env env = setPropertyInfo_->callBackInfo.env;
        status = napi_create_int32(env, result, &setPropertyInfo_->result);
        if (status != napi_ok) {
            HILOG_ERROR("napi_create_int32 faild");
        }
        if (setPropertyInfo_->callBackInfo.callBack != nullptr) {
            napi_value global = nullptr;
            status = napi_get_global(env, &global);
            if (status != napi_ok) {
                HILOG_ERROR("napi_get_global faild");
            }
            napi_value resultData[PARAM1];
            resultData[PARAM0] = setPropertyInfo_->result;
            setPropertyInfo_->result = nullptr;
            napi_value result = nullptr;
            napi_value callBack = nullptr;
            status = napi_get_reference_value(env, setPropertyInfo_->callBackInfo.callBack, &callBack);
            if (status != napi_ok) {
                HILOG_ERROR("napi_get_reference_value faild");
            }
            status = napi_call_function(env, global, callBack, PARAM1, resultData, &result);
            if (status != napi_ok) {
                HILOG_ERROR("napi_call_function faild");
            }
        } else {
            napi_value result = setPropertyInfo_->result;
            napi_deferred deferred = setPropertyInfo_->callBackInfo.deferred;
            status = napi_resolve_deferred(env, deferred, result);
            if (status != napi_ok) {
                HILOG_ERROR("napi_call_function faild");
            }
        }
        delete setPropertyInfo_;
        setPropertyInfo_ = nullptr;
    }
    HILOG_INFO("onSetExecutorProperty end");
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
