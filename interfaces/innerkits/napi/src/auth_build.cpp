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
    request.authType_ = convert.GetInt32ValueByKey(env, object, "authType");
    request.keys_ = convert.GetInt32ArrayValueByKey(env, object, "keys");
    HILOG_INFO(" AuthBuild::GetPropertyRequestBuild authType = %{public}d", request.authType_);
    return request;
}

bool AuthBuild::NapiTypeObject(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    napi_valuetype isObject = convert.GetType(env, value);
    if (isObject == napi_object) {
        return true;
    }
    return false;
}

bool AuthBuild::NapiTypeNumber(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    napi_valuetype isNumber = convert.GetType(env, value);
    if (isNumber == napi_number) {
        return true;
    }
    return false;
}

uint64_t AuthBuild::GetUint8ArrayTo64(napi_env env, napi_value value)
{
    napi_typedarray_type arraytype;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    uint8_t *data = nullptr;
    bool isTypedArray = false;
    napi_is_typedarray(env, value, &isTypedArray);
    if (!isTypedArray) {
        HILOG_ERROR("GetUint8ArrayTo64 value is not typedarray");
        return 0;
    }
    napi_get_typedarray_info(env, value, &arraytype, &length, reinterpret_cast<void **>(&data), &buffer, &offset);
    if (arraytype != napi_uint8_array) {
        HILOG_ERROR("GetUint8ArrayTo64 js value is not uint8Array");
        return 0;
    }
    if (offset != 0) {
        HILOG_ERROR("offset is %{public}d", offset);
        return 0;
    }
    std::vector<uint8_t> result(data, data + length);
    uint8_t tmp[sizeof(uint64_t)];
    for (uint32_t i = 0; i < sizeof(uint64_t); i++) {
        tmp[i] = result[i];
        HILOG_INFO("GetUint8ArrayTo64 result is %{public}d", (unsigned)result[i]);
    }
    uint64_t *re = static_cast<uint64_t *>(static_cast<void *>(tmp));
    HILOG_INFO("GetUint8ArrayTo64 resultUint64 is %{public}llu", *re);
    return *re;
}

int AuthBuild::NapiGetValueInt(napi_env env, napi_value value)
{
    return convert.NapiGetValueInt(env, value);
}

napi_value AuthBuild::Uint64ToUint8Array(napi_env env, uint64_t value)
{
    return convert.Uint64ToUint8Napi(env, value);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
