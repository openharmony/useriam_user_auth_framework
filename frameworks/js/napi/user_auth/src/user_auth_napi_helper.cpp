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

#include "user_auth_napi_helper.h"

#include <string>
#include <uv.h>

#include "securec.h"

#include "napi/native_common.h"

#include "iam_logger.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const std::map<UserAuthResultCode, std::string> g_resultV92Str = {
    {UserAuthResultCode::OHOS_INVALID_PARAM, "Invalid authentication parameters."},
    {UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED, "Permission denied."},
    {UserAuthResultCode::SUCCESS, "Authentication succeeded."},
    {UserAuthResultCode::FAIL, "Authentication failed."},
    {UserAuthResultCode::GENERAL_ERROR, "Unknown errors."},
    {UserAuthResultCode::CANCELED, "Authentication canceled."},
    {UserAuthResultCode::TIMEOUT, "Authentication timeout."},
    {UserAuthResultCode::TYPE_NOT_SUPPORT, "Unsupport authentication type."},
    {UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT, "Unsupport authentication trust level."},
    {UserAuthResultCode::BUSY, "Authentication service is busy."},
    {UserAuthResultCode::LOCKED, "Authentication is lockout."},
    {UserAuthResultCode::NOT_ENROLLED, "Authentication template has not been enrolled."},
};

struct DeleteRefHolder {
    napi_env env {nullptr};
    napi_ref ref {nullptr};
};

void DestoryDeleteWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<DeleteRefHolder *>(work->data));
    }
    delete work;
}

void OnDeleteRefWork(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    DeleteRefHolder *deleteRefHolder = reinterpret_cast<DeleteRefHolder *>(work->data);
    if (deleteRefHolder == nullptr) {
        IAM_LOGE("deleteRefHolder is invalid");
        DestoryDeleteWork(work);
        return;
    }
    napi_status ret = napi_delete_reference(deleteRefHolder->env, deleteRefHolder->ref);
    if (ret != napi_ok) {
        IAM_LOGE("napi_delete_reference fail %{public}d", ret);
        DestoryDeleteWork(work);
        return;
    }
    DestoryDeleteWork(work);
}
}

JsRefHolder::JsRefHolder(napi_env env, napi_value value)
{
    if (env == nullptr || value == nullptr) {
        IAM_LOGE("get null ptr");
        return;
    }
    napi_status ret = UserAuthNapiHelper::GetFunctionRef(env, value, ref_);
    if (ret != napi_ok) {
        IAM_LOGE("GetFunctionRef fail %{public}d", ret);
        ref_ = nullptr;
        return;
    }
    env_ = env;
}

JsRefHolder::~JsRefHolder()
{
    if (!IsValid()) {
        IAM_LOGI("invalid");
        return;
    }
    IAM_LOGI("delete reference");
    uv_loop_s *loop;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    DeleteRefHolder *deleteRefHolder = new (std::nothrow) DeleteRefHolder();
    if (deleteRefHolder == nullptr) {
        IAM_LOGE("deleteRefHolder is null");
        delete work;
        return;
    }
    deleteRefHolder->env = env_;
    deleteRefHolder->ref = ref_;
    work->data = reinterpret_cast<void *>(deleteRefHolder);
    if (uv_queue_work(loop, work, [](uv_work_t *work) {}, OnDeleteRefWork) != 0) {
        IAM_LOGE("uv_queue_work fail");
        DestoryDeleteWork(work);
    }
    env_ = nullptr;
    ref_ = nullptr;
}

bool JsRefHolder::IsValid() const
{
    return (env_ != nullptr && ref_ != nullptr);
}

napi_ref JsRefHolder::Get() const
{
    return ref_;
}

int32_t UserAuthNapiHelper::GetResultCodeV8(int32_t result)
{
    if (result == CHECK_PERMISSION_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED);
    }
    if ((result < SUCCESS) || (result > NOT_ENROLLED)) {
        return GENERAL_ERROR;
    }
    return result;
}

int32_t UserAuthNapiHelper::GetResultCodeV9(int32_t result)
{
    if (result == CHECK_PERMISSION_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED);
    }
    if (result == INVALID_PARAMETERS) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_INVALID_PARAM);
    }
    if (result > (INT32_MAX - static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V9_MIN))) {
        return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
    }
    int32_t resultCodeV9 = result + static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V9_MIN);
    if (resultCodeV9 >= static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V9_MIN) &&
        resultCodeV9 <= static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V9_MAX)) {
        return resultCodeV9;
    }
    return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
}

napi_value UserAuthNapiHelper::GenerateBusinessErrorV9(napi_env env, UserAuthResultCode result)
{
    napi_value code;
    std::string msgStr;
    auto res = g_resultV92Str.find(result);
    if (res == g_resultV92Str.end()) {
        IAM_LOGE("result %{public}d not found", static_cast<int32_t>(result));
        msgStr = g_resultV92Str.at(UserAuthResultCode::GENERAL_ERROR);
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR), &code));
    } else {
        msgStr = res->second;
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(result), &code));
    }
    IAM_LOGI("get msg %{public}s", msgStr.c_str());

    napi_value msg;
    NAPI_CALL(env, napi_create_string_utf8(env, msgStr.c_str(), NAPI_AUTO_LENGTH, &msg));

    napi_value businessError;
    NAPI_CALL(env, napi_create_error(env, nullptr, msg, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", code));

    return businessError;
}

napi_status UserAuthNapiHelper::CheckNapiType(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valuetype;
    napi_status result = napi_typeof(env, value, &valuetype);
    if (result != napi_ok) {
        IAM_LOGE("napi_typeof fail");
        return result;
    }
    if (valuetype != type) {
        IAM_LOGE("check valuetype fail");
        return napi_generic_failure;
    }
    return napi_ok;
}

napi_status UserAuthNapiHelper::GetInt32Value(napi_env env, napi_value value, int32_t &out)
{
    napi_status result = CheckNapiType(env, value, napi_number);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_get_value_int32(env, value, &out);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_value_int32 fail");
    }
    return result;
}

napi_status UserAuthNapiHelper::GetUint32Value(napi_env env, napi_value value, uint32_t &out)
{
    napi_status result = CheckNapiType(env, value, napi_number);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_get_value_uint32(env, value, &out);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_value_uint32 fail");
    }
    return result;
}

napi_status UserAuthNapiHelper::GetStrValue(napi_env env, napi_value value, char *out, size_t &len)
{
    napi_status result = CheckNapiType(env, value, napi_string);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    size_t maxLen = len;
    result = napi_get_value_string_utf8(env, value, out, maxLen, &len);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_value_string_utf8 fail");
    }
    if (out != nullptr && maxLen > 0) {
        out[maxLen - 1] = '\0';
    }
    return result;
}

napi_status UserAuthNapiHelper::GetFunctionRef(napi_env env, napi_value value, napi_ref &ref)
{
    napi_status result = CheckNapiType(env, value, napi_function);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_create_reference(env, value, 1, &ref);
    if (result != napi_ok) {
        IAM_LOGE("napi_create_reference fail");
    }
    return result;
}

napi_status UserAuthNapiHelper::GetUint8ArrayValue(napi_env env, napi_value value,
    size_t limitLen, std::vector<uint8_t> &array)
{
    bool isTypedarray;
    napi_status result = napi_is_typedarray(env, value, &isTypedarray);
    if (result != napi_ok) {
        IAM_LOGE("napi_is_typedarray fail");
        return result;
    }
    if (!isTypedarray) {
        IAM_LOGE("value is not typedarray");
        return napi_array_expected;
    }
    napi_typedarray_type type;
    size_t length;
    void *data;
    napi_value buffer;
    size_t offset;
    result = napi_get_typedarray_info(env, value, &type, &length, &data, &buffer, &offset);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_typedarray_info fail");
        return result;
    }
    if (type != napi_uint8_array) {
        IAM_LOGE("value is not napi_uint8_array");
        return napi_invalid_arg;
    }
    if (length > limitLen) {
        IAM_LOGE("array length reach limit");
        return napi_generic_failure;
    }
    array.resize(length);
    if (memcpy_s(array.data(), length, data, length) != EOK) {
        IAM_LOGE("memcpy_s fail");
        return napi_generic_failure;
    }
    return result;
}

napi_value UserAuthNapiHelper::Uint64ToNapiUint8Array(napi_env env, uint64_t value)
{
    void *data = nullptr;
    napi_value arraybuffer = nullptr;
    size_t length = sizeof(value);
    NAPI_CALL(env, napi_create_arraybuffer(env, length, &data, &arraybuffer));
    if (memcpy_s(data, length, reinterpret_cast<const void *>(&value), length) != EOK) {
        IAM_LOGE("memcpy_s fail");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, length, arraybuffer, 0, &result));
    return result;
}

napi_status UserAuthNapiHelper::CallVoidNapiFunc(napi_env env, napi_ref funcRef, size_t argc, const napi_value *argv)
{
    napi_value funcVal;
    napi_status ret = napi_get_reference_value(env, funcRef, &funcVal);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_reference_value failed %{public}d", ret);
        return ret;
    }
    napi_value undefined;
    ret = napi_get_undefined(env, &undefined);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_undefined failed %{public}d", ret);
        return ret;
    }
    napi_value callResult;
    ret = napi_call_function(env, undefined, funcVal, argc, argv, &callResult);
    if (ret != napi_ok) {
        IAM_LOGE("napi_call_function failed %{public}d", ret);
    }
    return ret;
}

napi_status UserAuthNapiHelper::SetInt32Property(napi_env env, napi_value obj, const char *name, int32_t value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_create_int32(env, value, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_status UserAuthNapiHelper::SetUint32Property(napi_env env, napi_value obj, const char *name, uint32_t value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_create_uint32(env, value, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_uint32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_status UserAuthNapiHelper::SetUint8ArrayProperty(napi_env env,
    napi_value obj, const char *name, const std::vector<uint8_t> &value)
{
    size_t size = value.size();
    void *data;
    napi_value buffer;
    napi_status ret = napi_create_arraybuffer(env, size, &data, &buffer);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_arraybuffer failed %{public}d", ret);
        return ret;
    }
    if (size != 0) {
        if (memcpy_s(data, size, value.data(), value.size()) != EOK) {
            IAM_LOGE("memcpy_s failed");
            return napi_generic_failure;
        }
    }
    napi_value napiValue;
    ret = napi_create_typedarray(env, napi_uint8_array, size, buffer, 0, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_typedarray failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS