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

#include "securec.h"
#include "auth_hilog_wrapper.h"
#include "result_convert.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
ResultConvert::ResultConvert(void)
{
}

ResultConvert::~ResultConvert()
{
}

napi_value ResultConvert::BuildArrayExecutorProperty(napi_env env, Napi_ExecutorProperty property)
{
    napi_value jsObject = nullptr;
    napi_create_object(env, &jsObject);
    SetPropertyInt(env, jsObject, property.result_, "result");
    SetPropertyInt(env, jsObject, property.authSubType_, "authSubType");
    SetPropertyUint(env, jsObject, property.remainTimes_, "remainTimes");
    SetPropertyUint(env, jsObject, property.freezingTime_, "freezingTime");
    return jsObject;
}

std::vector<uint8_t> ResultConvert::ConvertUint8(uint64_t value)
{
    std::string number = std::to_string(value); // trimmed to fit
    int length = number.length();
    HILOG_INFO("ResultConvert ConvertUint8 strat result %{public}d", length);
    std::vector<uint8_t> uint8Array;
    for (int i = 0; i < length; i++) {
        char charVlaue = number.at(i);
        uint8_t result = (uint8_t)atoi(&charVlaue);
        HILOG_INFO("ResultConvert ConvertUint8 strat result %{public}u", result);
        uint8Array.push_back(result);
    }
    return uint8Array;
}

napi_value ResultConvert::BuildNapiUint8Array(napi_env env, std::vector<uint8_t> value)
{
    HILOG_INFO("ResultConvert SetPropertyUint8ArrayTest strat ");
    void *data = nullptr;
    napi_value buffer = nullptr;
    NAPI_CALL(env, napi_create_arraybuffer(env, value.size(), &data, &buffer));
    if (memcpy_s(data, value.size(), value.data(), value.size()) != 0) {
        HILOG_INFO("ResultConvert SetPropertyUint8ArrayTest error");
        return nullptr;
    }
    napi_value keyValue = nullptr;
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, value.size(), buffer, 0, &keyValue));
    return keyValue;
}

void ResultConvert::SetPropertyUint8ArrayTest(
    napi_env env, napi_value &jsObject, std::vector<uint8_t> value, std::string key)
{
    napi_status status;
    napi_value keyValue = BuildNapiUint8Array(env, value);
    if (keyValue == nullptr) {
        status = napi_create_int64(env, -1, &keyValue);
        if (status != napi_ok) {
            HILOG_ERROR("napi_create_int64 faild");
        }
    }
    napi_value resultKey = nullptr;
    status = napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &resultKey);
    if (status != napi_ok) {
            HILOG_ERROR("napi_create_string_utf8 faild");
    }
    status = napi_set_property(env, jsObject, resultKey, keyValue);
    if (status != napi_ok) {
            HILOG_ERROR("napi_set_property faild");
    }
    HILOG_INFO("ResultConvert SetPropertyUint8ArrayTest end");
}

void ResultConvert::SetPropertyUint8Array(napi_env env, napi_value &jsObject, uint64_t value, std::string key)
{
    HILOG_INFO("BuildArrayExecutorProperty SetPropertyUint8Array strat");
    napi_status status;
    napi_value keyValue = GetAuthInfoRet(env, value);
    napi_value resultKey = nullptr;
    status = napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &resultKey);
    if (status != napi_ok) {
            HILOG_ERROR("napi_create_string_utf8 faild");
    }
    status = napi_set_property(env, jsObject, resultKey, keyValue);
    if (status != napi_ok) {
            HILOG_ERROR("napi_set_property faild");
    }
    HILOG_INFO("BuildArrayExecutorProperty SetPropertyUint8Array end");
}

napi_value ResultConvert::GetAuthInfoRet(napi_env env, uint64_t Ret)
{
    HILOG_INFO("GetAuthInfoRet  strat");
    std::string RetCode = std::to_string(Ret);
    size_t bufefersize;
    void *cdata = nullptr;
    napi_value arrayBuffer = nullptr;
    const char *CCrets = RetCode.c_str();
    bufefersize = RetCode.size();
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_arraybuffer(env, bufefersize, &cdata, &arrayBuffer));
    if (memcpy_s(cdata, bufefersize, reinterpret_cast<const void *>(CCrets), bufefersize) != EOK) {
        HILOG_INFO("memcpy_s failed");
    }
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, bufefersize, arrayBuffer, 0, &result));
    HILOG_INFO("GetAuthInfoRet  end");
    return result;
}

void ResultConvert::SetPropertyInt(napi_env env, napi_value &jsObject, int32_t value, std::string key)
{
    napi_status status;
    napi_value keyValue = 0;
    status = napi_create_int32(env, value, &keyValue);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_int32 faild");
    }
    napi_value resultKey = nullptr;
    status = napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &resultKey);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_string_utf8 faild");
    }
    status = napi_set_property(env, jsObject, resultKey, keyValue);
    if (status != napi_ok) {
        HILOG_ERROR("napi_set_property faild");
    }
}

void ResultConvert::SetPropertyUint(napi_env env, napi_value &jsObject, uint32_t value, std::string key)
{
    napi_status status;
    napi_value keyValue = 0;
    status = napi_create_uint32(env, value, &keyValue);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_uint32 faild");
    }
    napi_value resultKey = nullptr;
    status = napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &resultKey);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_string_utf8 faild");
    }
    status = napi_set_property(env, jsObject, resultKey, keyValue);
    if (status != napi_ok) {
        HILOG_ERROR("napi_set_property faild");
    }
}

void ResultConvert::SetPropertyBigint(napi_env env, napi_value &jsObject, uint64_t value, std::string key)
{
    napi_status status;
    napi_value keyValue = 0;
    status = napi_create_bigint_uint64(env, value, &keyValue);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_bigint_uint64 faild");
    }
    napi_value resultKey = nullptr;
    status = napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &resultKey);
    if (status != napi_ok) {
        HILOG_ERROR("napi_create_string_utf8 faild");
    }
    status = napi_set_property(env, jsObject, resultKey, keyValue);
    if (status != napi_ok) {
        HILOG_ERROR("napi_set_property faild");
    }
}

std::vector<std::uint8_t> ResultConvert::NapiGetValueUint8Array(napi_env env, napi_value jsObject, std::string key)
{
    napi_value jsValue = GetNapiValue(env, key.c_str(), jsObject);
    std::vector<uint8_t> RetNull;
    if (jsValue == nullptr) {
        return RetNull;
    }
    napi_typedarray_type arraytype;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    uint8_t *data = nullptr;
    bool isTypedArray = false;
    napi_is_typedarray(env, jsValue, &isTypedArray);
    if (isTypedArray) {
        HILOG_INFO("args[PIN_PARAMS_ONE]  is a array");
    } else {
        HILOG_INFO("args[PIN_PARAMS_ONE]  is not a uint8array");
    }
    napi_get_typedarray_info(env, jsValue, &arraytype, &length, reinterpret_cast<void **>(&data), &buffer, &offset);
    if (arraytype == napi_uint8_array) {
        HILOG_INFO("InputerImpl, OnSetData get uint8 array ");
    } else {
        HILOG_ERROR("InputerImpl, OnSetData get uint8 array error");
        return RetNull;
        }
    if (offset != 0) {
        HILOG_INFO(" offset is =============>%{public}d", offset);
        return RetNull;
    }
    std::vector<uint8_t> result(data, data+length);
    return result;
}

napi_valuetype ResultConvert::GetType(napi_env env, napi_value value)
{
    napi_status status;
    if (value == nullptr) {
        return napi_null;
    }
    napi_valuetype type;
    status = napi_typeof(env, value, &type);
    if (status != napi_ok) {
        HILOG_ERROR("napi_typeof faild");
    }
    return type;
}

std::string ResultConvert::GetStringValueByKey(napi_env env, napi_value jsObject, std::string key)
{
    napi_value value = GetNapiValue(env, key.c_str(), jsObject);
    std::string result = NapiGetValueString(env, value);
    return result;
}

int32_t ResultConvert::GetInt32ValueByKey(napi_env env, napi_value jsObject, std::string key)
{
    napi_value value = GetNapiValue(env, key.c_str(), jsObject);
    return NapiGetValueInt32(env, value);
}

std::vector<uint32_t> ResultConvert::GetInt32ArrayValueByKey(napi_env env, napi_value jsObject, std::string key)
{
    napi_status status;
    napi_value array = GetNapiValue(env, key.c_str(), jsObject);
    std::vector<uint32_t> values;
    if (array == nullptr) {
        return values;
    }
    std::vector<uint32_t>RetNull = {0};
    napi_typedarray_type arraytype;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    uint8_t *data = nullptr;
    bool isTypedArray = false;
    status = napi_is_typedarray(env, array, &isTypedArray);
    if (status != napi_ok) {
        HILOG_INFO("napi_is_typedarray is failed");
    }
    if (isTypedArray) {
        HILOG_INFO("args[PIN_PARAMS_ONE]  is a array");
    } else {
        HILOG_INFO("args[PIN_PARAMS_ONE]  is not a uint8array");
        return RetNull;
    }
    status = napi_get_typedarray_info(env, array, &arraytype, &length, reinterpret_cast<void **>(&data), &buffer, &offset);
    if (status != napi_ok) {
        HILOG_INFO("napi_get_typedarray_info is failed");
    }
    if (arraytype == napi_uint32_array) {
        HILOG_INFO("InputerImpl, OnSetData get uint8 array ");
    } else {
        HILOG_ERROR("InputerImpl, OnSetData get uint8 array error");
        return RetNull;
    }
    if (offset != 0) {
        HILOG_INFO(" offset is =============>%{public}d",offset);
        return RetNull;
    }
    std::vector<uint32_t>result(data, data + length);
    return result;
}

std::string ResultConvert::NapiGetValueString(napi_env env, napi_value value)
{
    napi_status status;
    if (value == nullptr) {
        HILOG_ERROR("AuthBuild NapiGetValueString value is nullptr");
        return "";
    }
    std::string resultValue = "";
    char valueString[NAPI_GET_STRING_SIZE];
    size_t valueSize = NAPI_GET_STRING_SIZE;
    size_t resultSize = 0;
    status =napi_get_value_string_utf8(env, value, valueString, valueSize, &resultSize);
    if (status != napi_ok) {
        HILOG_ERROR("napi_get_value_string_utf8 faild");
    }
    resultValue = valueString;
    if (resultValue == "") {
        HILOG_ERROR("ContactsBuild NapiGetValueString Data error");
        return "";
    }
    return resultValue;
}

int32_t ResultConvert::NapiGetValueInt32(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return GET_VALUE_ERROR;
    }
    int32_t result;
    napi_status status = napi_get_value_int32(env, value, &result);
    if (status != napi_ok) {
        return GET_VALUE_ERROR;
    }
    return result;
}

int ResultConvert::NapiGetValueInt(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return GET_VALUE_ERROR;
    }
    int32_t result;
    napi_status status = napi_get_value_int32(env, value, &result);
    if (status != napi_ok) {
        return GET_VALUE_ERROR;
    }
    int ret = result;
    return ret;
}

napi_value ResultConvert::GetNapiValue(napi_env env, const std::string keyChar, napi_value object)
{
    if (object == nullptr) {
        HILOG_ERROR("ResultConvert::GetNapiValue object is nullptr");
        return nullptr;
    }
    napi_value key = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, keyChar.c_str(), NAPI_AUTO_LENGTH, &key));
    bool result = false;
    NAPI_CALL(env, napi_has_property(env, object, key, &result));
    if (result) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_get_property(env, object, key, &value));
        return value;
    }
    return nullptr;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS