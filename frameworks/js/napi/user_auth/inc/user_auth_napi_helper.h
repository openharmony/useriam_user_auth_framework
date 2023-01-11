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

#ifndef USER_AUTH_NAPI_HELPER
#define USER_AUTH_NAPI_HELPER

#include <vector>

#include "napi/native_api.h"

#include "nocopyable.h"

#include "auth_common.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthNapiHelper {
public:
    static napi_value GenerateBusinessErrorV9(napi_env env, UserAuthResultCode result);
    static napi_status CheckNapiType(napi_env env, napi_value value, napi_valuetype type);
    static napi_status GetInt32Value(napi_env env, napi_value value, int32_t &out);
    static napi_status GetUint32Value(napi_env env, napi_value value, uint32_t &out);
    static napi_status GetStrValue(napi_env env, napi_value value, char *out, size_t &len);
    static napi_status GetFunctionRef(napi_env env, napi_value value, napi_ref &ref);
    static napi_status GetUint8ArrayValue(napi_env env, napi_value value,
        size_t limitLen, std::vector<uint8_t> &array);
    static napi_value Uint64ToNapiUint8Array(napi_env env, uint64_t value);
    static napi_status SetInt32Property(napi_env env, napi_value obj, const char *name, int32_t value);
    static napi_status SetUint32Property(napi_env env, napi_value obj, const char *name, uint32_t value);
    static napi_status SetUint8ArrayProperty(napi_env env,
        napi_value obj, const char *name, const std::vector<uint8_t> &value);
    static napi_status CallVoidNapiFunc(napi_env env, napi_ref funcRef, size_t argc, const napi_value *argv);
    static int32_t GetResultCodeV8(int32_t result);
    static int32_t GetResultCodeV9(int32_t result);

private:
    UserAuthNapiHelper() = default;
    ~UserAuthNapiHelper() = default;
};

class JsRefHolder : public NoCopyable {
public:
    JsRefHolder(napi_env env, napi_value value);
    ~JsRefHolder() override;
    bool IsValid() const;
    napi_ref Get() const;

private:
    napi_env env_ {nullptr};
    napi_ref ref_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_NAPI_HELPER