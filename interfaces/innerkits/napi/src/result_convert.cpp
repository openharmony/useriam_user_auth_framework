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

#include "result_convert.h"

#include "securec.h"

#include "auth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
ResultConvert::ResultConvert(void)
{
}

ResultConvert::~ResultConvert()
{
}

napi_value ResultConvert::Uint64ToUint8Napi(napi_env env, uint64_t value)
{
    HILOG_INFO("ResultConvert Uint64ToUint8Napi uint64_t %{public}llu", value);
    size_t length = sizeof(value);
    void *data = nullptr;
    napi_value arrayBuffer = nullptr;
    size_t bufferSize = length;
    NAPI_CALL(env, napi_create_arraybuffer(env, bufferSize, &data, &arrayBuffer));
    memcpy_s(data, bufferSize, reinterpret_cast<const void *>(&value), bufferSize);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, bufferSize, arrayBuffer, 0, &result));
    return result;
}

std::vector<uint8_t> ResultConvert::NapiGetValueUint8Array(napi_env env, napi_value jsObject, std::string key)
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
    if (!isTypedArray) {
        HILOG_ERROR("NapiGetValueUint8Array jsValue is not typedarray");
        return RetNull;
    }
    napi_get_typedarray_info(env, jsValue, &arraytype, &length, reinterpret_cast<void **>(&data), &buffer, &offset);
    if (arraytype != napi_uint8_array) {
        HILOG_ERROR("NapiGetValueUint8Array js jsValue is not uint8Array");
        return RetNull;
    }
    if (offset != 0) {
        HILOG_ERROR("offset is %{public}d", offset);
        return RetNull;
    }
    std::vector<uint8_t> result(data, data + length);
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

std::vector<uint32_t> ResultConvert::GetCppArrayUint32(napi_env env, napi_value value)
{
    napi_status status;
    uint32_t arrayLength = 0;
    napi_get_array_length(env, value, &arrayLength);
    if (arrayLength <= 0) {
        HILOG_ERROR("%{public}s The array is empty.", __func__);
        return std::vector<uint32_t>();
    }
    std::vector<uint32_t> paramArrays;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiElement = nullptr;
        napi_get_element(env, value, i, &napiElement);
        napi_valuetype napiValueType = napi_undefined;
        napi_typeof(env, napiElement, &napiValueType);
        if (napiValueType != napi_number) {
            HILOG_ERROR("%{public}s Wrong argument type. Numbers expected.", __func__);
            return std::vector<uint32_t>();
        }
        uint32_t napiValue = 0;
        status = napi_get_value_uint32(env, napiElement, &napiValue);
        if (status != napi_ok) {
            return std::vector<uint32_t>();
        }
        paramArrays.push_back(napiValue);
    }
    return paramArrays;
}

std::vector<uint32_t> ResultConvert::GetInt32ArrayValueByKey(napi_env env, napi_value jsObject, std::string key)
{
    napi_status status;
    napi_value array = GetNapiValue(env, key.c_str(), jsObject);
    if (array == nullptr) {
        return std::vector<uint32_t>();
    }
    bool isArray = false;
    status = napi_is_array(env, array, &isArray);
    if (status != napi_ok) {
        HILOG_INFO("napi_is_array is failed");
        return std::vector<uint32_t>();
    }
    if (isArray) {
        HILOG_INFO("args[PIN_PARAMS_ONE]  is a array");
    } else {
        HILOG_INFO("args[PIN_PARAMS_ONE]  is not a array");
        return std::vector<uint32_t>();
    }
    return GetCppArrayUint32(env, array);
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
    status = napi_get_value_string_utf8(env, value, valueString, valueSize, &resultSize);
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
