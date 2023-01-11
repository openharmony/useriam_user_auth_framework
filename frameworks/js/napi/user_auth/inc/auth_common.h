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
constexpr size_t ARGS_ZERO = 0;
constexpr size_t ARGS_ONE = 1;
constexpr size_t ARGS_TWO = 2;
constexpr size_t ARGS_THREE = 3;
constexpr size_t ARGS_FOUR = 4;

constexpr size_t PARAM0 = 0;
constexpr size_t PARAM1 = 1;
constexpr size_t PARAM2 = 2;
constexpr size_t PARAM3 = 3;

constexpr int32_t API_VERSION_6 = 6;
constexpr int32_t API_VERSION_8 = 8;
constexpr int32_t API_VERSION_9 = 9;

// For API6
enum class AuthenticationResult : int32_t {
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

enum class UserAuthResultCode : int32_t {
    OHOS_CHECK_PERMISSION_FAILED = 201,
    OHOS_INVALID_PARAM = 401,
    RESULT_CODE_V9_MIN = 12500000,
    SUCCESS = 12500000,
    FAIL = 12500001,
    GENERAL_ERROR = 12500002,
    CANCELED = 12500003,
    TIMEOUT = 12500004,
    TYPE_NOT_SUPPORT = 12500005,
    TRUST_LEVEL_NOT_SUPPORT = 12500006,
    BUSY = 12500007,
    LOCKED = 12500009,
    NOT_ENROLLED = 12500010,
    RESULT_CODE_V9_MAX = 12500010,
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif /* OHOS_USERAUTH_COMMON_H */
