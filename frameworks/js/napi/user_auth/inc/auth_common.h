/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
constexpr int32_t API_VERSION_10 = 10;
constexpr int32_t API_VERSION_12 = 12;

constexpr const char *NOTICE_EVENT_AUTH_READY = "EVENT_AUTH_TYPE_READY";
constexpr const char *NOTICE_EVENT_CANCEL_AUTH = "EVENT_AUTH_USER_CANCEL";
constexpr const char *NOTICE_EVENT_USER_NAVIGATION = "EVENT_AUTH_USER_NAVIGATION";
constexpr const char *NOTICE_EVENT_WIDGET_PARA_INVALID = "EVENT_AUTH_WIDGET_PARA_INVALID";
constexpr const char *NOTICE_EVENT_END = "EVENT_AUTH_END";

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
    OHOS_CHECK_SYSTEM_APP_FAILED = 202,
    OHOS_INVALID_PARAM = 401,
    RESULT_CODE_V9_MIN = 12500000,
    RESULT_CODE_V10_MIN = 12500000,
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
    CANCELED_FROM_WIDGET = 12500011,
    PIN_EXPIRED = 12500013,
    RESULT_CODE_V10_MAX = 12500013,
};

enum FaceTipsCode {
    FACE_AUTH_TIP_TOO_BRIGHT = 1,
    FACE_AUTH_TIP_TOO_DARK = 2,
    FACE_AUTH_TIP_TOO_CLOSE = 3,
    FACE_AUTH_TIP_TOO_FAR = 4,
    FACE_AUTH_TIP_TOO_HIGH = 5,
    FACE_AUTH_TIP_TOO_LOW = 6,
    FACE_AUTH_TIP_TOO_RIGHT = 7,
    FACE_AUTH_TIP_TOO_LEFT = 8,
    FACE_AUTH_TIP_TOO_MUCH_MOTION = 9,
    FACE_AUTH_TIP_POOR_GAZE = 10,
    FACE_AUTH_TIP_NOT_DETECTED = 11,
    FACE_AUTH_TIP_MAX = FACE_AUTH_TIP_NOT_DETECTED,
};

enum FingerprintTips {
    FINGERPRINT_AUTH_TIP_GOOD = 0,
    FINGERPRINT_AUTH_TIP_IMAGER_DIRTY = 1,
    FINGERPRINT_AUTH_TIP_INSUFFICIENT = 2,
    FINGERPRINT_AUTH_TIP_PARTIAL = 3,
    FINGERPRINT_AUTH_TIP_TOO_FAST = 4,
    FINGERPRINT_AUTH_TIP_TOO_SLOW = 5,
    FINGERPRINT_AUTH_TIP_MAX = FINGERPRINT_AUTH_TIP_TOO_SLOW,
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif /* OHOS_USERAUTH_COMMON_H */
