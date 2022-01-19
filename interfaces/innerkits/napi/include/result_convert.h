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

#ifndef RESULT_CONVERT_H
#define RESULT_CONVERT_H

#include <string>
#include <vector>

#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "auth_common.h"
#include "auth_object.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class ResultConvert {
public:
    ResultConvert();
    ~ResultConvert();
    std::vector<uint8_t> NapiGetValueUint8Array(napi_env env, napi_value jsObject, std::string key);
    napi_value BuildArrayExecutorProperty(napi_env env, Napi_ExecutorProperty property);
    napi_valuetype GetType(napi_env env, napi_value value);
    std::string GetStringValueByKey(napi_env env, napi_value jsObject, std::string key);
    int32_t NapiGetValueInt32(napi_env env, napi_value value);
    std::vector<uint32_t> GetInt32ArrayValueByKey(napi_env env, napi_value jsObject, std::string key);
    int32_t GetInt32ValueByKey(napi_env env, napi_value jsObject, std::string key);
    int NapiGetValueInt(napi_env env, napi_value value);
    void SetPropertyUint8Array(napi_env env, napi_value &jsObject, uint64_t value, std::string key);
    napi_value GetAuthInfoRet(napi_env env, uint64_t Ret);
    void SetPropertyUint8ArrayTest(napi_env env, napi_value &jsObject, std::vector<uint8_t> value, std::string key);
    std::vector<uint8_t> ConvertUint8(uint64_t value);
    napi_value BuildNapiUint8Array(napi_env env, std::vector<uint8_t> value);

private:
    void SetPropertyInt(napi_env env, napi_value &jsObject, int32_t value, std::string key);
    void SetPropertyUint(napi_env env, napi_value &jsObject, uint32_t value, std::string key);
    void SetPropertyBigint(napi_env env, napi_value &jsObject, uint64_t value, std::string key);
    std::string NapiGetValueString(napi_env env, napi_value value);
    napi_value GetNapiValue(napi_env env, const std::string keyChar, napi_value object);
    std::vector<uint32_t> GetCppArrayUint32(napi_env env, napi_value value);
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // RESULT_CONVERT_H
