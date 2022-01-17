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

#include "auth_build.h"

#include "auth_common.h"
#include "auth_hilog_wrapper.h"
#include "auth_object.h"
#include "result_convert.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
AuthBuild::AuthBuild(void)
{
}
AuthBuild::~AuthBuild()
{
}

Napi_SetPropertyRequest AuthBuild::SetPropertyRequestBuild(napi_env env, napi_value object)
{
    Napi_SetPropertyRequest request;
    if (object == nullptr) {
        HILOG_ERROR("SetPropertyRequestBuild object is null ");
        return request;
    }
    UserAuth::ResultConvert convert;
    request.authType_ = convert.GetInt32ValueByKey(env, object, "authType");
    request.key_ = convert.GetInt32ValueByKey(env, object, "key");
    request.setInfo_ = convert.NapiGetValueUint8Array(env, object, "setInfo");
    HILOG_INFO(" AuthBuild::SetPropertyRequestBuild authType = %{public}d", request.authType_);
    HILOG_INFO(" AuthBuild::SetPropertyRequestBuild key = %{public}d", request.key_);
    return request;
}

Napi_GetPropertyRequest AuthBuild::GetPropertyRequestBuild(napi_env env, napi_value object)
{
    Napi_GetPropertyRequest request;
    if (object == nullptr) {
        HILOG_ERROR("GetPropertyRequestBuild object is null ");
        return request;
    }
    UserAuth::ResultConvert convert;
    request.authType_ = convert.GetInt32ValueByKey(env, object, "authType");
    request.keys_ = convert.GetInt32ArrayValueByKey(env, object, "keys");
    HILOG_INFO(" AuthBuild::GetPropertyRequestBuild authType = %{public}d", request.authType_);
    return request;
}

napi_value AuthBuild::GetNapiExecutorProperty(napi_env env, Napi_ExecutorProperty property)
{
    ResultConvert convert;
    return convert.BuildArrayExecutorProperty(env, property);
}

bool AuthBuild::NapiTypeObject(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    ResultConvert convert;
    napi_valuetype isObject = convert.GetType(env, value);
    if (isObject == napi_object) {
        return true;
    }
    return false;
}

bool AuthBuild::NapiTypeBitInt(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    ResultConvert convert;
    napi_valuetype isBigInt = convert.GetType(env, value);
    if (isBigInt == napi_bigint) {
        return true;
    }
    return false;
}

bool AuthBuild::NapiTypeNumber(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    ResultConvert convert;
    napi_valuetype isNumber = convert.GetType(env, value);
    if (isNumber == napi_number) {
        return true;
    }
    return false;
}

napi_value AuthBuild::BuildAuthResult(napi_env env, Napi_AuthResult authResult)
{
    HILOG_INFO("BuildAuthResult start");
    napi_value object = nullptr;
    NAPI_CALL(env, napi_create_object(env, &object));

    napi_value keyToken = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "token", NAPI_AUTO_LENGTH, &keyToken));

    ResultConvert convert;
    napi_value token = convert.BuildNapiUint8Array(env, authResult.token_);
    NAPI_CALL(env, napi_set_property(env, object, keyToken, token));

    napi_value keyRemainTimes = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "remainTimes", NAPI_AUTO_LENGTH, &keyRemainTimes));
    uint32_t remainTimes = authResult.remainTimes_;
    napi_value remainTimesValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, remainTimes, &remainTimesValue));
    NAPI_CALL(env, napi_set_property(env, object, keyRemainTimes, remainTimesValue));

    napi_value keyFreezingTime = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "freezingTime", NAPI_AUTO_LENGTH, &keyFreezingTime));
    uint32_t freezingTime = authResult.freezingTime_;
    napi_value freezingTimeValue = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, freezingTime, &freezingTimeValue));
    NAPI_CALL(env, napi_set_property(env, object, keyFreezingTime, freezingTimeValue));
    HILOG_INFO("BuildAuthResult end");
    return object;
}

void AuthBuild::AuthUserCallBackResult(napi_env env, AuthUserInfo *userInfo)
{
    HILOG_INFO("%{public}s, start ", __func__);
    napi_status status;
    int32_t result = userInfo->result;
    napi_value dataResult = 0;
    status = napi_create_int32(env, result, &dataResult);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_int32 faild");
    }
    userInfo->onResultData[0] = dataResult;

    napi_value resultExtraInfo = BuildAuthResult(env, userInfo->authResult);
    userInfo->onResultData[1] = resultExtraInfo;
    HILOG_INFO("%{public}s,  end", __func__);
}

void AuthBuild::AuthUserCallBackAcquireInfo(napi_env env, AuthUserInfo *userInfo)
{
    HILOG_INFO("%{public}s, start ", __func__);
    napi_value jsModule = 0;
    napi_status status;
    int32_t jsModeValue = userInfo->module;
    status = napi_create_int32(env, jsModeValue, &jsModule);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_int32 faild");
    }
    userInfo->onAcquireInfoData[0] = jsModule;
    napi_value acquire = 0;
    uint32_t acquireValue = userInfo->acquireInfo;
    status = napi_create_uint32(env, acquireValue, &acquire);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_uint32 faild");
    }
    userInfo->onAcquireInfoData[1] = acquire;

    if (userInfo->extraInfoIsNull) {
        napi_value result = 0;
        status = napi_get_null(env, &result);
        if (status != napi_ok) {
            HILOG_ERROR("napi_get_null faild");
        }
        userInfo->onAcquireInfoData[ARGS_TWO] = result;
    } else {
        HILOG_INFO("%{public}s, extraInfo Is not Null ", __func__);
        napi_value result = 0;
        status = napi_get_null(env, &result);
        if (status != napi_ok) {
            HILOG_ERROR("napi_get_null faild");
        }
        userInfo->onAcquireInfoData[ARGS_TWO] = result;
    }
}

void AuthBuild::AuthCallBackAcquireInfo(napi_env env, AuthInfo *authInfo)
{
    HILOG_INFO("%{public}s, start ", __func__);
    napi_status status;
    napi_value jsModule = 0;
    int32_t jsModeValue = authInfo->module;
    status = napi_create_int32(env, jsModeValue, &jsModule);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_int32 faild");
    }
    authInfo->onAcquireInfoData[0] = jsModule;
    napi_value acquire = 0;
    uint32_t acquireValue = authInfo->acquireInfo;
    status = napi_create_uint32(env, acquireValue, &acquire);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_uint32 faild");
    }
    authInfo->onAcquireInfoData[1] = acquire;

    if (authInfo->extraInfoIsNull) {
        napi_value result = 0;
        status = napi_get_null(env, &result);
        if (status != napi_ok) {
            HILOG_ERROR("napi_get_null faild");
        }
        authInfo->onAcquireInfoData[ARGS_TWO] = result;
    } else {
        HILOG_INFO("%{public}s, extraInfo Is not Null ", __func__);
        napi_value result = 0;
        status = napi_get_null(env, &result);
        if (status != napi_ok) {
            HILOG_ERROR("napi_get_null faild");
        }
        authInfo->onAcquireInfoData[ARGS_TWO] = result;
    }
    HILOG_INFO("%{public}s,  end", __func__);
}

void AuthBuild::AuthCallBackResult(napi_env env, AuthInfo *authInfo)
{
    HILOG_INFO("%{public}s, start ", __func__);
    napi_status status;
    int32_t result = authInfo->result;
    napi_value dataResult = 0;
    status = napi_create_int32(env, result, &dataResult);
    if (status != napi_ok) {
        HILOG_ERROR("napi_get_null faild");
    }
    authInfo->onResultData[0] = dataResult;

    napi_value resultExtraInfo = BuildAuthResult(env, authInfo->authResult);
    authInfo->onResultData[1] = resultExtraInfo;
    HILOG_INFO("%{public}s,  end", __func__);
}

uint64_t AuthBuild::GetUint8ArrayTo64(napi_env env, napi_value value)
{
    napi_typedarray_type arraytype;
    std::string challenge;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    uint8_t *data = nullptr;
    bool isTypedArray = false;
    napi_is_typedarray(env, value, &isTypedArray);
    if (isTypedArray) {
        HILOG_INFO("args[PIN_PARAMS_ONE]  is a array");
    } else {
        HILOG_INFO("args[PIN_PARAMS_ONE]  is not a uint8array");
    }
    napi_get_typedarray_info(env, value, &arraytype, &length, reinterpret_cast<void **>(&data), &buffer, &offset);
    if (arraytype == napi_uint8_array) {
        HILOG_INFO("InputerImpl, OnSetData get uint8 array ");
    } else {
        HILOG_ERROR("InputerImpl, OnSetData get uint8 array error");
        return 0;
        }
    if (offset != 0) {
        HILOG_INFO(" offset is =============>%{public}d", offset);
        return 0;
    }
    std::vector<uint8_t> result(data, data+length);
    challenge.assign(result.begin(), result.end());
    uint64_t resultUint64 = atol(challenge.c_str());
    return resultUint64;
}

int AuthBuild::NapiGetValueInt(napi_env env, napi_value value)
{
    ResultConvert convert;
    return convert.NapiGetValueInt(env, value);
}
napi_value AuthBuild::Uint64ToUint8Array(napi_env env, uint64_t value)
{
    ResultConvert convert;
    return convert.BuildNapiUint8Array(env, convert.ConvertUint8(value));
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS