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

#include "auth_build.h"

#include <cinttypes>

#include "securec.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "auth_common.h"
#include "auth_object.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
AuthBuild::AuthBuild() = default;
AuthBuild::~AuthBuild() = default;

Napi_SetPropertyRequest AuthBuild::SetPropertyRequestBuild(napi_env env, napi_value object)
{
    Napi_SetPropertyRequest request;
    if (object == nullptr) {
        IAM_LOGE("object is null");
        return request;
    }
    request.authType_ = convert_.GetInt32ValueByKey(env, object, "authType");
    request.key_ = static_cast<uint32_t>(convert_.GetInt32ValueByKey(env, object, "key"));
    request.setInfo_ = convert_.NapiGetValueUint8Array(env, object, "setInfo");
    IAM_LOGI("authType = %{public}d", request.authType_);
    return request;
}

Napi_GetPropertyRequest AuthBuild::GetPropertyRequestBuild(napi_env env, napi_value object)
{
    Napi_GetPropertyRequest request;
    if (object == nullptr) {
        IAM_LOGE("object is null");
        return request;
    }
    request.authType_ = convert_.GetInt32ValueByKey(env, object, "authType");
    request.keys_ = convert_.GetInt32ArrayValueByKey(env, object, "keys");
    IAM_LOGI("authType = %{public}d", request.authType_);
    return request;
}

bool AuthBuild::NapiTypeObject(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    napi_valuetype isObject = convert_.GetType(env, value);
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
    napi_valuetype isNumber = convert_.GetType(env, value);
    if (isNumber == napi_number) {
        return true;
    }
    return false;
}

uint64_t AuthBuild::GetUint8ArrayTo64(napi_env env, napi_value value)
{
    std::vector<uint8_t> result = GetUint8Array(env, value);
    if (result.size() != sizeof(uint64_t)) {
        IAM_LOGE("size is invalid");
        return 0;
    }
    uint64_t valueU64;
    if (memcpy_s(&valueU64, sizeof(valueU64), result.data(), result.size()) != EOK) {
        IAM_LOGE("failed to copy value");
        return valueU64;
    }
    return valueU64;
}

std::vector<uint8_t> AuthBuild::GetUint8Array(napi_env env, napi_value value)
{
    napi_typedarray_type arraytype;
    size_t length = 0;
    napi_value buffer = nullptr;
    size_t offset = 0;
    uint8_t *data = nullptr;
    bool isTypedArray = false;
    napi_is_typedarray(env, value, &isTypedArray);
    if (!isTypedArray) {
        IAM_LOGE("value is not typedarray");
        return {};
    }
    napi_get_typedarray_info(env, value, &arraytype, &length, reinterpret_cast<void **>(&data), &buffer, &offset);
    if (arraytype != napi_uint8_array) {
        IAM_LOGE("value is not uint8Array");
        return {};
    }
    if (offset != 0) {
        IAM_LOGE("offset is %{public}zu", offset);
        return {};
    }
    std::vector<uint8_t> result(data, data + length);
    return result;
}

int32_t AuthBuild::NapiGetValueInt32(napi_env env, napi_value value)
{
    return convert_.NapiGetValueInt32(env, value);
}

napi_value AuthBuild::Uint64ToUint8Array(napi_env env, uint64_t value)
{
    return convert_.Uint64ToUint8Napi(env, value);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
