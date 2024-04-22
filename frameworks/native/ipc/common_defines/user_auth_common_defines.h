/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

/**
 * @file user_auth_common_defines.h
 *
 * @brief Some common defines in IAM.
 * @since 3.1
 * @version 3.2
 */

#ifndef USER_AUTH_COMMON_DEFINES_H
#define USER_AUTH_COMMON_DEFINES_H

#include <cstddef>
#include <cstdint>

#include <string>
#include <vector>

#include "iam_common_defines.h"
#include "user_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

const std::string NOTICE_VERSION_STR = "1";
const std::string CMD_NOTIFY_AUTH_START = "CMD_NOTIFY_AUTH_START";
const std::string CMD_NOTIFY_AUTH_RESULT = "CMD_NOTIFY_AUTH_RESULT";
const std::string CMD_NOTIFY_AUTH_TIP = "CMD_NOTIFY_AUTH_TIP";
const uint64_t MAX_ALLOWABLE_REUSE_DURATION = 5 * 60 * 1000;

/**
 * @brief Notice type for user authentication.
 */
enum NoticeType : int32_t {
    /** notice from widget. */
    WIDGET_NOTICE = 1,
};

/**
 * @brief Window mode type for user authentication widget.
 */
enum WindowModeType : int32_t {
    /** Window mode type is dialog box. */
    DIALOG_BOX = 1,
    /**  Window mode type is full screen. */
    FULLSCREEN = 2,
    /**  Window mode type is not set */
    UNKNOWN_WINDOW_MODE = 3,
};

/**
 * @brief The mode for reusing unlock authentication result.
 */
enum ReuseMode : uint32_t {
    /** Authentication type relevant.The unlock authentication result can be reused only when the result is within
     * valid duration as well as it comes from one of specified UserAuthTypes of the AuthParam. */
    AUTH_TYPE_RELEVANT = 1,
    /** Authentication type irrelevant.The unlock authentication result can be reused as long as the result is within
     * valid duration. */
    AUTH_TYPE_IRRELEVANT = 2,
};

/**
 * @brief Reuse unlock authentication result.
 */
struct ReuseUnlockResult {
    /** Whether to reuse unlock result, ReuseUnlockResult is valid only when isReuse is true.*/
    bool isReuse {false};
    /** The mode for reusing unlock authentication result. */
    ReuseMode reuseMode {AUTH_TYPE_IRRELEVANT};
    /** The allowable reuse duration.The value of duration should be between 0 and MAX_ALLOWABLE_REUSE_DURATION. */
    uint64_t reuseDuration {0};
};

/**
 * @brief Auth parameter.
 */
struct AuthParamInner {
    /** user id */
    int32_t userId;
    /** challenge value */
    std::vector<uint8_t> challenge;
    /** Credential type for authentication. */
    AuthType authType;
    /** Credential type for authentication. */
    std::vector<AuthType> authTypes;
    /** Trust level of authentication result. */
    AuthTrustLevel authTrustLevel;
    /** Reuse unlock authentication result. */
    ReuseUnlockResult reuseUnlockResult;
    /** Auth intent. */
    AuthIntent authIntent;
};

/**
 * @brief EnrolledId digest and credential count.
 */
struct EnrolledState {
    /** The credential digest. */
    uint64_t credentialDigest {0};
    /** The credential count */
    uint16_t credentialCount {0};
};

/**
 * @brief Auth widget parameter.
 */
struct WidgetParam {
    /** Title of widget. */
    std::string title;
    /** The description text of navigation button. */
    std::string navigationButtonText;
    /** Full screen or not. */
    WindowModeType windowMode;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_COMMON_DEFINES_H
