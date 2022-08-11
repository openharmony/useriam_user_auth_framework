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

#ifndef RESULT_CONVERT_H
#define RESULT_CONVERT_H

#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "nocopyable.h"

#include "auth_common.h"
#include "user_auth_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ResultConvert {
public:
    DISALLOW_COPY_AND_MOVE(ResultConvert);
    ResultConvert();
    virtual ~ResultConvert();
    napi_value Uint64ToUint8Napi(napi_env env, uint64_t value);
    napi_valuetype GetType(napi_env env, napi_value value);
    std::string GetStringValueByKey(napi_env env, napi_value jsObject, std::string key);
    int32_t GetInt32ValueByKey(napi_env env, napi_value jsObject, std::string key);
    int32_t NapiGetValueInt32(napi_env env, napi_value value);
    std::vector<uint32_t> GetInt32ArrayValueByKey(napi_env env, napi_value jsObject, std::string key);

private:
    std::vector<uint32_t> GetCppArrayUint32(napi_env env, napi_value value);
    std::string NapiGetValueString(napi_env env, napi_value value);
    napi_value GetNapiValue(napi_env env, const std::string keyChar, napi_value object);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // RESULT_CONVERT_H
