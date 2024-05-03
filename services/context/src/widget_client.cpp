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

#include "auth_common.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_time.h"
#include "nlohmann/json.hpp"
#include "widget_callback_interface.h"
#include "hisysevent_adapter.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

const std::string PIN_SUB_TYPE_SIX = "PIN_SIX";
const std::string PIN_SUB_TYPE_NUMBER = "PIN_NUMBER";
const std::string PIN_SUB_TYPE_MIXED = "PIN_MIXED";
const std::string PIN_SUB_TYPE_MAX = "PIN_MAX";

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
    if (type != WIDGET_NOTICE) {
        IAM_LOGE("Invalid notice type");
        return ResultCode::INVALID_PARAMETERS;
    }
    if (eventData.empty()) {
        IAM_LOGE("Invalid notice event data");
        return ResultCode::INVALID_PARAMETERS;
    }
    IAM_LOGI("recv notice eventData: %{public}s", eventData.c_str());
    auto root = nlohmann::json::parse(eventData.c_str(), nullptr, false);
    if (root.is_null() || root.is_discarded()) {
        IAM_LOGE("OnNotice eventData is not json format");
        return ResultCode::INVALID_PARAMETERS;
    }
    WidgetNotice notice = root.get<WidgetNotice>();
    if (notice.widgetContextId == 0) {
        IAM_LOGE("Invalid widget context id");
        return ResultCode::INVALID_PARAMETERS;
    }
    if (!IsValidNoticeType(notice)) {
        IAM_LOGE("Not support notice event");
        return ResultCode::INVALID_PARAMETERS;
    }
    if (schedule_ == nullptr) {
        IAM_LOGE("Invalid schedule node, report auth false");
        return ResultCode::GENERAL_ERROR;
    }
    std::vector<AuthType> authTypeList = {};
    if (!GetAuthTypeList(notice, authTypeList)) {
        IAM_LOGE("Invalid auth type list");
        return ResultCode::INVALID_PARAMETERS;
    }
    if (notice.event == NOTICE_EVENT_AUTH_READY) {
        schedule_->StartAuthList(authTypeList, notice.endAfterFirstFail);
    } else if (notice.event == NOTICE_EVENT_CANCEL_AUTH) {
        if (authTypeList.size() == 1 && authTypeList[0] == AuthType::ALL) {
            schedule_->StopSchedule();
        } else {
            schedule_->StopAuthList(authTypeList);
        }
    } else if (notice.event == NOTICE_EVENT_USER_NAVIGATION) {
        schedule_->NaviPinAuth();
    } else if (notice.event == NOTICE_EVENT_WIDGET_PARA_INVALID) {
        schedule_->WidgetParaInvalid();
    } else if (notice.event == NOTICE_EVENT_END) {
        schedule_->StopAuthList(authTypeList);
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
    IAM_LOGI("SendCommand cmdData");
    widgetCallback_->SendCommand(cmdData);
}

void WidgetClient::ReportWidgetResult(int32_t result, AuthType authType,
    int32_t lockoutDuration, int32_t remainAttempts)
{
    WidgetCommand::ExtraInfo extraInfo {
        .callingBundleName = callingBundleName_,
        .challenge = challenge_
    };
    // sendCommand of CMD_NOTIFY_AUTH_RESULT
    WidgetCommand::Cmd cmd {
        .event = CMD_NOTIFY_AUTH_RESULT,
        .version = NOTICE_VERSION_STR,
        .type = AuthType2Str(authType),
        .result = result,
        .lockoutDuration = lockoutDuration,
        .remainAttempts = remainAttempts,
        .extraInfo = extraInfo
    };
    if (authType == AuthType::FINGERPRINT && !sensorInfo_.empty()) {
        cmd.sensorInfo = sensorInfo_;
    }
    WidgetCommand widgetCmd {
        .widgetContextId = widgetContextId_,
        .title = widgetParam_.title,
        .windowModeType = WinModeType2Str(widgetParam_.windowMode),
        .navigationButtonText = widgetParam_.navigationButtonText,
        .cmdList = { cmd }
    };
    for (auto &type : authTypeList_) {
        widgetCmd.typeList.emplace_back(AuthType2Str(type));
    }
    if (!pinSubType_.empty()) {
        widgetCmd.pinSubType = pinSubType_;
    }
    SendCommand(widgetCmd);
}

void WidgetClient::ReportWidgetTip(int32_t tipType, AuthType authType, std::vector<uint8_t> tipInfo)
{
    // sendCommand of CMD_NOTIFY_AUTH_TIP
    WidgetCommand::Cmd cmd {
        .event = CMD_NOTIFY_AUTH_TIP,
        .version = NOTICE_VERSION_STR,
        .type = AuthType2Str(authType),
        .tipType = tipType,
        .tipInfo = tipInfo
    };
    WidgetCommand widgetCmd {
        .widgetContextId = widgetContextId_,
        .cmdList = { cmd }
    };
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

void WidgetClient::SetAuthTypeList(const std::vector<AuthType> &authTypeList)
{
    authTypeList_ = authTypeList;
}

void WidgetClient::SetWidgetCallback(const sptr<WidgetCallbackInterface> &callback)
{
    widgetCallback_ = callback;
}

void WidgetClient::SetAuthTokenId(uint32_t tokenId)
{
    authTokenId_ = tokenId;
    IAM_LOGI("WidgetClient SetAuthTokenId authTokenId: %{public}u", authTokenId_);
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
    if (widgetContextId_ != 0) {
        IAM_LOGE("widget context id hasn't been reset");
        UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "AuthWidget");
    }
    if (schedule_ != nullptr) {
        schedule_->StopSchedule();
    }
}

void WidgetClient::SetPinSubType(const PinSubType &subType)
{
    pinSubType_ = PIN_SUB_TYPE_SIX;
    switch (subType) {
        case PinSubType::PIN_NUMBER:
            pinSubType_ = PIN_SUB_TYPE_NUMBER;
            break;
        case PinSubType::PIN_MIXED:
            pinSubType_ = PIN_SUB_TYPE_MIXED;
            break;
        case PinSubType::PIN_MAX:
            pinSubType_ = PIN_SUB_TYPE_MAX;
            break;
        default:
            break;
    }
}

void WidgetClient::SetSensorInfo(const std::string &info)
{
    sensorInfo_ = info;
}

bool WidgetClient::GetAuthTypeList(const WidgetNotice &notice, std::vector<AuthType> &authTypeList)
{
    if (authTypeList_.empty()) {
        IAM_LOGE("inner auth type list is empty");
        return false;
    }
    std::vector<AuthType> tempList = notice.AuthTypeList();
    if (tempList.empty()) {
        IAM_LOGE("auth type list is empty");
        return false;
    }
    if (tempList.size() == 1 && tempList[0] == AuthType::ALL) {
        if (notice.event != NOTICE_EVENT_CANCEL_AUTH) {
            IAM_LOGE("invalid type all case event type: %{public}s", notice.event.c_str());
            return false;
        }
        authTypeList.emplace_back(AuthType::ALL);
        return true;
    }
    for (auto &type : tempList) {
        if (std::find(authTypeList_.begin(), authTypeList_.end(), type) == authTypeList_.end()) {
            IAM_LOGE("invalid auth type: %{public}d", type);
            return false;
        }
        authTypeList.emplace_back(type);
    }
    if (authTypeList.size() == authTypeList_.size() && notice.event == NOTICE_EVENT_CANCEL_AUTH) {
        authTypeList.clear();
        authTypeList.emplace_back(AuthType::ALL);
    }
    return true;
}

bool WidgetClient::IsValidNoticeType(const WidgetNotice &notice)
{
    if (notice.event != NOTICE_EVENT_AUTH_READY &&
        notice.event != NOTICE_EVENT_CANCEL_AUTH &&
        notice.event != NOTICE_EVENT_USER_NAVIGATION &&
        notice.event != NOTICE_EVENT_WIDGET_PARA_INVALID &&
        notice.event != NOTICE_EVENT_END) {
        return false;
    }
    return true;
}

void WidgetClient::SetChallenge(const std::vector<uint8_t> &challenge)
{
    challenge_ = challenge;
}

void WidgetClient::SetCallingBundleName(const std::string &callingBundleName)
{
    callingBundleName_ = callingBundleName;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS