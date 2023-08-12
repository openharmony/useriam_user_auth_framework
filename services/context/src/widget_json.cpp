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

#include <map>
#include "iam_common_defines.h"
#include "user_auth_common_defines.h"
#include "widget_json.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

const std::string AUTH_TYPE_PIN = "pin";
const std::string AUTH_TYPE_FACE = "face";
const std::string AUTH_TYPE_FINGER_PRINT = "fingerprint";
const std::string AUTH_TYPE_ALL = "all";

const std::string WINDOW_MODE_DIALOG = "DIALOG_BOX";
const std::string WINDOW_MODE_FULLSCREEN = "FULLSCREEN";

const std::string PIN_SUB_TYPE_SIX = "PIN_SIX";
const std::string PIN_SUB_TYPE_NUM = "PIN_NUMBER";
const std::string PIN_SUB_TYPE_MIX = "PIN_MIXED";
const std::string PIN_SUB_TYPE_MAX = "PIN_MAX";

const std::string JSON_AUTH_TYPE = "type";
const std::string JSON_WIDGET_CTX_ID = "widgetContextId";
const std::string JSON_AUTH_EVENT = "event";
const std::string JSON_AUTH_VERSION = "version";
const std::string JSON_AUTH_PAYLOAD = "payload";
const std::string JSON_LOCKOUT_DURATION = "lockoutDuration";
const std::string JSON_REMAIN_ATTEMPTS = "remainAttempts";
const std::string JSON_AUTH_RESULT = "result";
const std::string JSON_SENSOR_INFO = "sensorInfo";
const std::string JSON_AUTH_TIP = "tip";
const std::string JSON_AUTH_TITLE = "title";
const std::string JSON_AUTH_CMD = "cmd";
const std::string JSON_AUTH_PIN_SUB_TYPE = "pinSubType";
const std::string JSON_AUTH_WINDOW_MODE = "windowModeType";
const std::string JSON_AUTH_NAVI_BTN_TEXT = "navigationButtonText";

const std::string JSON_UI_EXTENSION_TYPE = "ability.want.params.uiExtensionType";
const std::string JSON_USER_IAM_CMD_DATA = "useriamCmdData";

// utils
AuthType Str2AuthType(const std::string &strAuthType)
{
    std::map<std::string, AuthType> authTypeMap;
    authTypeMap.emplace(std::make_pair(AUTH_TYPE_ALL, AuthType::ALL));
    authTypeMap.emplace(std::make_pair(AUTH_TYPE_PIN, AuthType::PIN));
    authTypeMap.emplace(std::make_pair(AUTH_TYPE_FACE, AuthType::FACE));
    authTypeMap.emplace(std::make_pair(AUTH_TYPE_FINGER_PRINT, AuthType::FINGERPRINT));
    auto result = AuthType::ALL;
    if (authTypeMap.find(strAuthType) != authTypeMap.end()) {
        result = authTypeMap[strAuthType];
    }
    return result;
}

std::string AuthType2Str(const AuthType &authType)
{
    std::map<int32_t, std::string> authTypeMap;
    authTypeMap.emplace(std::make_pair(AuthType::ALL, AUTH_TYPE_ALL));
    authTypeMap.emplace(std::make_pair(AuthType::PIN, AUTH_TYPE_PIN));
    authTypeMap.emplace(std::make_pair(AuthType::FACE, AUTH_TYPE_FACE));
    authTypeMap.emplace(std::make_pair(AuthType::FINGERPRINT, AUTH_TYPE_FINGER_PRINT));
    std::string result = "";
    if (authTypeMap.find(authType) != authTypeMap.end()) {
        result = authTypeMap[authType];
    }
    return result;
}

std::string WinModeType2Str(const WindowModeType &winModeType)
{
    std::map<int32_t, std::string> winModeTypeMap;
    winModeTypeMap.emplace(std::make_pair(WindowModeType::DIALOG_BOX, WINDOW_MODE_DIALOG));
    winModeTypeMap.emplace(std::make_pair(WindowModeType::FULLSCREEN, WINDOW_MODE_FULLSCREEN));
    std::string result = "";
    if (winModeTypeMap.find(winModeType) != winModeTypeMap.end()) {
        result = winModeTypeMap[winModeType];
    }
    return result;
}

std::vector<AuthType> WidgetNotice::AuthTypeList() const
{
    std::vector<AuthType> authTypeList;
    for (const auto &type : typeList) {
        authTypeList.emplace_back(Str2AuthType(type));
    }
    return authTypeList;
}

std::string PinSubType2Str(const PinSubType &subType)
{
    std::map<PinSubType, std::string> pinSubTypeMap;
    pinSubTypeMap.emplace(std::make_pair(PinSubType::PIN_SIX, PIN_SUB_TYPE_SIX));
    pinSubTypeMap.emplace(std::make_pair(PinSubType::PIN_NUMBER, PIN_SUB_TYPE_NUM));
    pinSubTypeMap.emplace(std::make_pair(PinSubType::PIN_MIXED, PIN_SUB_TYPE_MIX));
    pinSubTypeMap.emplace(std::make_pair(PinSubType::PIN_MAX, PIN_SUB_TYPE_MAX));

    std::string result = "";
    if (pinSubTypeMap.find(subType) != pinSubTypeMap.end()) {
        result = pinSubTypeMap[subType];
    }
    return result;
}

void to_json(nlohmann::json &jsonNotice, const WidgetNotice &notice)
{
    auto type = nlohmann::json({{JSON_AUTH_TYPE, notice.typeList}});
    jsonNotice = nlohmann::json({{JSON_WIDGET_CTX_ID, notice.widgetContextId},
        {JSON_AUTH_EVENT, notice.event},
        {JSON_AUTH_VERSION, notice.version},
        {JSON_AUTH_PAYLOAD, type}});
}

void from_json(const nlohmann::json &jsonNotice, WidgetNotice &notice)
{
    if (jsonNotice.find(JSON_WIDGET_CTX_ID) != jsonNotice.end()) {
        jsonNotice.at(JSON_WIDGET_CTX_ID).get_to(notice.widgetContextId);
    }
    if (jsonNotice.find(JSON_AUTH_EVENT) != jsonNotice.end()) {
        jsonNotice.at(JSON_AUTH_EVENT).get_to(notice.event);
    }
    if (jsonNotice.find(JSON_AUTH_VERSION) != jsonNotice.end()) {
        jsonNotice.at(JSON_AUTH_VERSION).get_to(notice.version);
    }
    if (jsonNotice.find(JSON_AUTH_PAYLOAD) != jsonNotice.end() ||
        jsonNotice[JSON_AUTH_PAYLOAD].find(JSON_AUTH_TYPE) == jsonNotice[JSON_AUTH_PAYLOAD].end() ||
        !jsonNotice[JSON_AUTH_PAYLOAD][JSON_AUTH_TYPE].is_array()) {
        jsonNotice.at(JSON_AUTH_PAYLOAD).at(JSON_AUTH_TYPE).get_to(notice.typeList);
    }
}

void to_json(nlohmann::json &jsonCommand, const WidgetCommand &command)
{
    std::vector<nlohmann::json> jsonCmdList;
    for (auto &cmd : command.cmdList) {
        auto jsonCmd = nlohmann::json({{JSON_AUTH_EVENT, cmd.event},
            {JSON_AUTH_VERSION, cmd.version}
        });
        auto jsonPayload = nlohmann::json({{JSON_AUTH_TYPE, cmd.type}});
        if (cmd.lockoutDuration != -1) {
            jsonPayload[JSON_LOCKOUT_DURATION] = cmd.lockoutDuration;
        }
        if (cmd.remainAttempts != -1) {
            jsonPayload[JSON_REMAIN_ATTEMPTS] = cmd.remainAttempts;
        }
        if (cmd.event == "CMD_NOTIFY_AUTH_RESULT") {
            jsonPayload[JSON_AUTH_RESULT] = cmd.result;
        }
        if (cmd.sensorInfo != "") {
            jsonPayload[JSON_SENSOR_INFO] = cmd.sensorInfo;
        }
        if (cmd.tip != "") {
            jsonPayload[JSON_AUTH_TIP] = cmd.tip;
        }
        jsonCmd[JSON_AUTH_PAYLOAD] = jsonPayload;
        jsonCmdList.push_back(jsonCmd);
    }

    jsonCommand = nlohmann::json({{JSON_WIDGET_CTX_ID, command.widgetContextId},
        {JSON_AUTH_TYPE, command.typeList},
        {JSON_AUTH_TITLE, command.title},
        {JSON_AUTH_CMD, jsonCmdList}
    });
    if (command.pinSubType != "") {
        jsonCommand[JSON_AUTH_PIN_SUB_TYPE] = command.pinSubType;
    }
    if (command.windowModeType != "") {
        jsonCommand[JSON_AUTH_WINDOW_MODE] = command.windowModeType;
    }
    if (command.navigationButtonText != "") {
        jsonCommand[JSON_AUTH_NAVI_BTN_TEXT] = command.navigationButtonText;
    }
}

// WidgetCmdParameters
void to_json(nlohmann::json &jsWidgetCmdParam, const WidgetCmdParameters &widgetCmdParameters)
{
    std::vector<nlohmann::json> jsonCmdList;
    for (auto &cmd : widgetCmdParameters.useriamCmdData.cmdList) {
        auto jsonCmd = nlohmann::json({{JSON_AUTH_EVENT, cmd.event},
            {JSON_AUTH_VERSION, cmd.version}
        });
        auto jsonPayload = nlohmann::json({{JSON_AUTH_TYPE, cmd.type}});
        if (cmd.lockoutDuration != -1) {
            jsonPayload[JSON_LOCKOUT_DURATION] = cmd.lockoutDuration;
        }
        if (cmd.remainAttempts != -1) {
            jsonPayload[JSON_REMAIN_ATTEMPTS] = cmd.remainAttempts;
        }
        if (cmd.event == "CMD_NOTIFY_AUTH_RESULT") {
            jsonPayload[JSON_AUTH_RESULT] = cmd.result;
        }
        if (cmd.sensorInfo != "") {
            jsonPayload[JSON_SENSOR_INFO] = cmd.sensorInfo;
        }
        if (cmd.tip != "") {
            jsonPayload[JSON_AUTH_TIP] = cmd.tip;
        }
        jsonCmd[JSON_AUTH_PAYLOAD] = jsonPayload;
        jsonCmdList.push_back(jsonCmd);
    }

    auto jsCommand = nlohmann::json({{JSON_WIDGET_CTX_ID, widgetCmdParameters.useriamCmdData.widgetContextId},
        {JSON_AUTH_TYPE, widgetCmdParameters.useriamCmdData.typeList},
        {JSON_AUTH_TITLE, widgetCmdParameters.useriamCmdData.title},
        {JSON_AUTH_CMD, jsonCmdList}
    });

    if (widgetCmdParameters.useriamCmdData.pinSubType != "") {
        jsCommand[JSON_AUTH_PIN_SUB_TYPE] = widgetCmdParameters.useriamCmdData.pinSubType;
    }
    if (widgetCmdParameters.useriamCmdData.windowModeType != "") {
        jsCommand[JSON_AUTH_WINDOW_MODE] = widgetCmdParameters.useriamCmdData.windowModeType;
    }
    if (widgetCmdParameters.useriamCmdData.navigationButtonText != "") {
        jsCommand[JSON_AUTH_NAVI_BTN_TEXT] = widgetCmdParameters.useriamCmdData.navigationButtonText;
    }

    jsWidgetCmdParam = nlohmann::json({{JSON_UI_EXTENSION_TYPE, widgetCmdParameters.uiExtensionType},
        {JSON_USER_IAM_CMD_DATA, jsCommand}
    });
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS