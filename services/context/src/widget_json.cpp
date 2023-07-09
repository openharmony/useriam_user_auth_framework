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

#include "widget_json.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
// utils
AuthType Str2AuthType(const std::string &strAt)
{
    if (strAt == "pin") {
        return AuthType::PIN;
    } else if (strAt == "fingerprint") {
        return AuthType::FINGERPRINT;
    } else if (strAt == "face") {
        return AuthType::FACE;
    } else if (strAt == "all") {
        return AuthType::ALL;
    }
    return AuthType::ALL;
}

std::string AuthType2Str(const AuthType &at)
{
    static const std::string atArray[] = { "all", "pin", "face", "N/A", "fingerprint" };
    return atArray[static_cast<int32_t>(at)];
}

std::string WinModeType2Str(const WindowModeType &winModeType)
{
    static const std::string winModeTypeArray[] = { "N/A", "DIALOG_BOX", "FULLSCREEN" };
    return winModeTypeArray[static_cast<int32_t>(winModeType)];
}

std::vector<AuthType> WidgetNotice::AuthTypeList()
{
    std::vector<AuthType> atList;
    for (auto &type : typeList) {
        atList.push_back(Str2AuthType(type));
    }
    return atList;
}

std::string PinSubType2Str(const PinSubType &subType)
{
    if (subType == PinSubType::PIN_SIX) {
        return "PIN_SIX";
    } else if (subType == PinSubType::PIN_NUMBER) {
        return "PIN_NUMBER";
    } else if (subType == PinSubType::PIN_MIXED) {
        return "PIN_MIXED";
    } else if (subType == PinSubType::PIN_MAX) {
        return "PIN_MAX";
    }
    return "";
}

// WidgetNotice
void to_json(nlohmann::json &j, const WidgetNotice &notice)
{
    auto jsType = nlohmann::json({{"type", notice.typeList}});
    auto js = nlohmann::json({{"widgetContextId", notice.widgetContextId},
        {"event", notice.event},
        {"version", notice.version},
        {"payload", jsType}});
    j = js;
}

void from_json(const nlohmann::json &j, WidgetNotice &notice)
{
    j.at("widgetContextId").get_to(notice.widgetContextId);
    j.at("event").get_to(notice.event);
    j.at("version").get_to(notice.version);
    j.at("payload").at("type").get_to(notice.typeList);
}

// WidgetCommand
void to_json(nlohmann::json &j, const WidgetCommand &command)
{
    std::vector<nlohmann::json> jsCmdList;
    for (auto &cmd : command.cmdList) {
        nlohmann::json jsCmd = nlohmann::json({{"event", cmd.event},
            {"version", cmd.version}
        });
        auto jsPayload = nlohmann::json({{"type", cmd.type}});
        if (cmd.lockoutDuration != -1) {
            jsPayload["lockoutDuration"] = cmd.lockoutDuration;
        }
        if (cmd.remainAttempts != -1) {
            jsPayload["remainAttempts"] = cmd.remainAttempts;
        }
        if (cmd.event == "CMD_NOTIFY_AUTH_RESULT") {
            jsPayload["result"] = cmd.result;
        }
        if (!cmd.sensorInfo.empty()) {
            jsPayload["sensorInfo"] = cmd.sensorInfo;
        }
        if (!cmd.tip.empty()) {
            jsPayload["tip"] = cmd.tip;
        }
        jsCmd["payload"] = jsPayload;
        jsCmdList.push_back(jsCmd);
    }

    auto js = nlohmann::json({{"widgetContextId", command.widgetContextId},
        {"type", command.typeList},
        {"title", command.title},
        {"cmd", jsCmdList}
    });
    if (!command.pinSubType.empty()) {
        js["pinSubType"] = command.pinSubType;
    }
    if (!command.windowModeType.empty()) {
        js["windowModeType"] = command.windowModeType;
    }
    if (!command.navigationButtonText.empty()) {
        js["navigationButtonText"] = command.navigationButtonText;
    }
    j = js;
}

void from_json(const nlohmann::json &j, WidgetCommand &command)
{
}

// WidgetCmdParameters
void to_json(nlohmann::json &j, const WidgetCmdParameters &widgetCmdParameters)
{
    std::vector<nlohmann::json> jsCmdList;
    for (auto &cmd : widgetCmdParameters.useriamCmdData.cmdList) {
        nlohmann::json jsCmd = nlohmann::json({{"event", cmd.event},
            {"version", cmd.version}
        });
        auto jsPayload = nlohmann::json({{"type", cmd.type}});
        if (cmd.lockoutDuration != -1) {
            jsPayload["lockoutDuration"] = cmd.lockoutDuration;
        }
        if (cmd.remainAttempts != -1) {
            jsPayload["remainAttempts"] = cmd.remainAttempts;
        }
        if (cmd.event == "CMD_NOTIFY_AUTH_RESULT") {
            jsPayload["result"] = cmd.result;
        }
        if (!cmd.sensorInfo.empty()) {
            jsPayload["sensorInfo"] = cmd.sensorInfo;
        }
        if (!cmd.tip.empty()) {
            jsPayload["tip"] = cmd.tip;
        }
        jsCmd["payload"] = jsPayload;
        jsCmdList.push_back(jsCmd);
    }

    nlohmann::json jsCommand = nlohmann::json({{"widgetContextId", widgetCmdParameters.useriamCmdData.widgetContextId},
        {"type", widgetCmdParameters.useriamCmdData.typeList},
        {"title", widgetCmdParameters.useriamCmdData.title},
        {"cmd", jsCmdList}
    });

    if (!widgetCmdParameters.useriamCmdData.pinSubType.empty()) {
        jsCommand["pinSubType"] = widgetCmdParameters.useriamCmdData.pinSubType;
    }
    if (!widgetCmdParameters.useriamCmdData.windowModeType.empty()) {
        jsCommand["windowModeType"] = widgetCmdParameters.useriamCmdData.windowModeType;
    }
    if (!widgetCmdParameters.useriamCmdData.navigationButtonText.empty()) {
        jsCommand["navigationButtonText"] = widgetCmdParameters.useriamCmdData.navigationButtonText;
    }

    auto js = nlohmann::json({{"ability.want.params.uiExtensionType", widgetCmdParameters.uiExtensionType},
        {"useriamCmdData", jsCommand}
    });
    
    j = js;
}

void from_json(const nlohmann::json &j, WidgetCmdParameters &widgetCmdParameters)
{
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS