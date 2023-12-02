/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace UserIam {
namespace UserAuth {

const std::string NOTICE_VERSION_STR = "1";
const std::string CMD_NOTIFY_AUTH_START = "CMD_NOTIFY_AUTH_START";

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
 * @brief Auth parameter.
 */
struct AuthParam {
    /** challenge value */
    std::vector<uint8_t> challenge;
    /** Credential type for authentication. */
    std::vector<AuthType> authType;
    /** Trust level of authentication result. */
    AuthTrustLevel authTrustLevel;
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