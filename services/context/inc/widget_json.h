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

#ifndef IAM_WIDGET_JSON_H
#define IAM_WIDGET_JSON_H

#include <cstdint>
#include <memory>

#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "iam_common_defines.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
// utils
AuthType Str2AuthType(const std::string &strAuthType);
std::string AuthType2Str(const AuthType &authType);
std::string WinModeType2Str(const WindowModeType &winModeType);
std::string PinSubType2Str(const PinSubType &subType);

// WidgetNotice
struct WidgetNotice {
    std::vector<AuthType> AuthTypeList() const;

    // members
    uint64_t widgetContextId {0};
    std::string event {""};
    std::string version {""};
    std::vector<std::string> typeList {};
    bool endAfterFirstFail {false};
};
void to_json(nlohmann::json &jsonNotice, const WidgetNotice &notice);
void from_json(const nlohmann::json &jsonNotice, WidgetNotice &notice);

// WidgetCommand
struct WidgetCommand {
    struct ExtraInfo {
        std::string callingBundleName {""};
        std::vector<uint8_t> challenge {};
    };

    struct Cmd {
        std::string event {""};
        std::string version {""};
        std::string type {""};

        int32_t result = -1;
        int32_t lockoutDuration = -1;
        int32_t remainAttempts = -1;
        std::string sensorInfo {""};

        int32_t tipType = -1;
        std::vector<uint8_t> tipInfo;

        ExtraInfo extraInfo;
    };

    uint64_t widgetContextId {0};
    std::vector<std::string> typeList {};
    std::string title {""};
    std::string pinSubType {""};
    std::string windowModeType {""};
    std::string navigationButtonText {""};
    std::vector<Cmd> cmdList {};
};

void to_json(nlohmann::json &jsonCommand, const WidgetCommand &command);

// WidgetCmdParameters
struct WidgetCmdParameters {
    std::string uiExtensionType {""};
    WidgetCommand useriamCmdData {};
};

void to_json(nlohmann::json &jsonWidgetCmdParams, const WidgetCmdParameters &widgetCmdParameters);
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_JSON_H