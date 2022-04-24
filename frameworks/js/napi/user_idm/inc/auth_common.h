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

#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

#include "useridm_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "useridentity_manager.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class AuthCommon {
public:
    static napi_value CreateObject(napi_env env, const std::string& keyStr, uint64_t credentialId);
    static int32_t GetNamedProperty(napi_env env, napi_value obj, const std::string& keyStr);
    static std::vector<uint8_t> GetNamedAttribute(napi_env env, napi_value obj);
    static napi_status JudgeObjectType(napi_env env, napi_callback_info info,
        AsyncCallbackContext* asyncCallbackContext);
    static std::vector<uint8_t> JudgeArrayType(napi_env env, size_t argc, napi_value* argv);
    static void JudgeDelUserType(napi_env env, napi_callback_info info, AsyncCallbackContext* asyncCallbackContext);
    static void JudgeDelCredType(napi_env env, napi_callback_info info, AsyncCallbackContext* asyncCallbackContext);
    static void SaveCallback(napi_env env, size_t argc, napi_value* argv, AsyncCallbackContext* asyncCallbackContext);
};
} // namespace UserIDM
} // namespace UserIAM
} // namespace OHOS
#endif  // AUTH_COMMON_H
