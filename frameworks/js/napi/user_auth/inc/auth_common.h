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

#ifndef OHOS_USERAUTH_COMMON_H
#define OHOS_USERAUTH_COMMON_H

#include <map>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"

#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr size_t ARGS_ONE = 1;
constexpr size_t ARGS_TWO = 2;
constexpr size_t ARGS_THREE = 3;
constexpr size_t ARGS_FOUR = 4;

constexpr size_t PARAM0 = 0;
constexpr size_t PARAM1 = 1;
constexpr size_t PARAM2 = 2;
constexpr size_t PARAM3 = 3;

struct ExecuteInfo {
    explicit ExecuteInfo(napi_env napiEnv);
    ~ExecuteInfo();
    bool isPromise {false};
    napi_env env {nullptr};
    napi_ref callbackRef {nullptr};
    napi_deferred deferred {nullptr};
    napi_value promise {nullptr};
    int32_t result {0};
};

struct AuthInfo {
    explicit AuthInfo(napi_env napiEnv);
    ~AuthInfo();
    napi_env env {nullptr};
    napi_ref onResult {nullptr};
    napi_ref onAcquireInfo {nullptr};
    int32_t result {0};
    std::vector<uint8_t> token {};
    int32_t remainTimes {0};
    int32_t freezingTime {0};
};

// For API6
enum class AuthenticationResult {
    NO_SUPPORT = -1,
    SUCCESS = 0,
    COMPARE_FAILURE = 1,
    CANCELED = 2,
    TIMEOUT = 3,
    CAMERA_FAIL = 4,
    BUSY = 5,
    INVALID_PARAMETERS = 6,
    LOCKED = 7,
    NOT_ENROLLED = 8,
    GENERAL_ERROR = 100,
};

const std::map<int32_t, AuthenticationResult> result2ExecuteResult = {
    {ResultCode::SUCCESS, AuthenticationResult::SUCCESS},
    {ResultCode::FAIL, AuthenticationResult::COMPARE_FAILURE},
    {ResultCode::GENERAL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::CANCELED, AuthenticationResult::CANCELED},
    {ResultCode::TIMEOUT, AuthenticationResult::TIMEOUT},
    {ResultCode::TYPE_NOT_SUPPORT, AuthenticationResult::NO_SUPPORT},
    {ResultCode::TRUST_LEVEL_NOT_SUPPORT, AuthenticationResult::NO_SUPPORT},
    {ResultCode::BUSY, AuthenticationResult::BUSY},
    {ResultCode::INVALID_PARAMETERS, AuthenticationResult::INVALID_PARAMETERS},
    {ResultCode::LOCKED, AuthenticationResult::LOCKED},
    {ResultCode::NOT_ENROLLED, AuthenticationResult::NOT_ENROLLED},
    {ResultCode::IPC_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::INVALID_CONTEXT_ID, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::WRITE_PARCEL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::READ_PARCEL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::CHECK_PERMISSION_FAILED, AuthenticationResult::GENERAL_ERROR},
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif /* OHOS_USERAUTH_COMMON_H */
