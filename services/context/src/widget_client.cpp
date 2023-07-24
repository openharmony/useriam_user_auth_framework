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

#include "widget_client.h"

#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_time.h"
#include "nlohmann/json.hpp"
#include "widget_callback_interface.h"
#include "hisysevent_adapter.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetClient &WidgetClient::Instance()
{
    static WidgetClient widgetClient;
    return widgetClient;
}

void WidgetClient::SetWidgetSchedule(const std::shared_ptr<WidgetScheduleNode> &schedule)
{
    IF_FALSE_LOGE_AND_RETURN(schedule != nullptr);
    schedule_ = schedule;
}

ResultCode WidgetClient::OnNotice(NoticeType type, const std::string &eventData)
{
    // handle notice from widget
    if (eventData.empty()) {
        IAM_LOGE("OnNotice eventData is empty");
        return ResultCode::INVALID_PARAMETERS;
    }
    IAM_LOGI("recv notice eventData: %{public}s", eventData.c_str());
    auto root = nlohmann::json::parse(eventData.c_str(), nullptr, false);
    if (root.is_null() || root.is_discarded()) {
        IAM_LOGE("OnNotice eventData is not json format");
        return ResultCode::INVALID_PARAMETERS;
    }
    WidgetNotice notice = root.get<WidgetNotice>();
    if (notice.event != "EVENT_AUTH_TYPE_READY" &&
        notice.event != "EVENT_AUTH_USER_CANCEL" &&
        notice.event != "EVENT_AUTH_USER_NAVIGATION") {
        IAM_LOGE("OnNotice not support event");
        return ResultCode::INVALID_PARAMETERS;
    }
    std::vector<AuthType> authTypeList = notice.AuthTypeList();
    if (schedule_ == nullptr) {
        IAM_LOGE("Invalid schedule node, report auth false");
        ReportWidgetResult(0, AuthType::ALL, 0, 0);
        return ResultCode::SUCCESS;
    }
    if (notice.event == "EVENT_AUTH_TYPE_READY") {
        schedule_->StartAuthList(authTypeList);
    } else if (notice.event == "EVENT_AUTH_USER_CANCEL") {
        if (authTypeList.size() == 1 && authTypeList[0] == AuthType::ALL) {
            schedule_->StopSchedule();
        } else {
            schedule_->StopAuthList(authTypeList);
        }
    } else if (notice.event == "EVENT_AUTH_USER_NAVIGATION") {
        schedule_->NaviPinAuth();
    }
    return ResultCode::SUCCESS;
}

void WidgetClient::SendCommand(const WidgetCommand &command)
{
    if (widgetCallback_ == nullptr) {
        IAM_LOGE("SendCommand widget callback is null");
        return;
    }
    nlohmann::json root = command;
    std::string cmdData = root.dump();
    IAM_LOGI("SendCommand cmdData: %{public}s", cmdData.c_str());
    widgetCallback_->SendCommand(cmdData);
}

void WidgetClient::ReportWidgetResult(int32_t result, AuthType authType,
    int32_t lockoutDuration, int32_t remainAttempts)
{
    // sendCommand of CMD_NOTIFY_AUTH_RESULT
    WidgetCommand::Cmd cmd {
        .event = "CMD_NOTIFY_AUTH_RESULT",
        .version = NOTICE_VERSION_STR,
        .result = result,
        .type = AuthType2Str(authType),
        .lockoutDuration = lockoutDuration,
        .remainAttempts = remainAttempts
    };
    if (authType == AuthType::FINGERPRINT && !sensorInfo_.empty()) {
        cmd.sensorInfo = sensorInfo_;
    }
    WidgetCommand widgetCmd {
        .widgetContextId = widgetContextId_,
        .typeList = { AuthType2Str(authType) },
        .title = widgetParam_.title,
        .windowModeType = WinModeType2Str(widgetParam_.windowMode),
        .navigationButtonText = widgetParam_.navigationButtonText,
        .cmdList = { cmd }
    };
    if (!pinSubType_.empty()) {
        widgetCmd.pinSubType = pinSubType_;
    }
    SendCommand(widgetCmd);
}

void WidgetClient::SetWidgetContextId(uint64_t contextId)
{
    widgetContextId_ = contextId;
}

void WidgetClient::SetWidgetParam(const WidgetParam &param)
{
    widgetParam_ = param;
}

void WidgetClient::SetWidgetCallback(const sptr<WidgetCallbackInterface> &callback)
{
    widgetCallback_ = callback;
}

void WidgetClient::SetAuthTokenId(uint32_t tokenId)
{
    authTokenId_ = tokenId;
    IAM_LOGI("WidgetClient SetAuthTokenId authTokenId: %{public}d", authTokenId_);
}

uint32_t WidgetClient::GetAuthTokenId() const
{
    return authTokenId_;
}

void WidgetClient::Reset()
{
    IAM_LOGI("WidgetClient Reset");
    widgetParam_.title.clear();
    widgetParam_.navigationButtonText.clear();
    widgetParam_.windowMode = WindowModeType::DIALOG_BOX;
    widgetContextId_ = 0;
    authTokenId_ = 0;
    schedule_ = nullptr;
    widgetCallback_ = nullptr;
    pinSubType_.clear();
    sensorInfo_.clear();
}

void WidgetClient::ForceStopAuth()
{
    IAM_LOGE("Stop Auth process forcely by disconnect");
    if (schedule_ != nullptr) {
        schedule_->StopSchedule();
    }
    UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "AuthWidget");
}

void WidgetClient::SetPinSubType(const PinSubType &subType)
{
    switch (subType) {
        case PinSubType::PIN_SIX:
            pinSubType_ = "PIN_SIX";
            break;
        case PinSubType::PIN_NUMBER:
            pinSubType_ = "PIN_NUMBER";
            break;
        case PinSubType::PIN_MIXED:
            pinSubType_ = "PIN_MIXED";
            break;
        case PinSubType::PIN_MAX:
            pinSubType_ = "PIN_MAX";
            break;
        default:
            pinSubType_ = "PIN_SIX";
            break;
    }
}

void WidgetClient::SetSensorInfo(const std::string &info)
{
    sensorInfo_ = info;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS