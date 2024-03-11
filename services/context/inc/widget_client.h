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

#ifndef IAM_WIDGET_CLIENT_H
#define IAM_WIDGET_CLIENT_H

#include <cstdint>
#include <memory>
#include <set>
#include <vector>

#include "authentication_impl.h"
#include "widget_callback_interface.h"
#include "widget_json.h"
#include "widget_schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetClient {
public:
    static WidgetClient &Instance();
    ~WidgetClient() = default;
    // sets
    void SetWidgetSchedule(const std::shared_ptr<WidgetScheduleNode> &schedule);
    void SetWidgetContextId(uint64_t contextId);
    void SetWidgetParam(const WidgetParam &param);
    void SetAuthTypeList(const std::vector<AuthType> &authTypeList);
    void SetWidgetCallback(const sptr<WidgetCallbackInterface> &callback);
    void SetAuthTokenId(uint32_t tokenId);
    uint32_t GetAuthTokenId() const;

    // interaction with widget
    ResultCode OnNotice(NoticeType type, const std::string &eventData);
    void ReportWidgetResult(int32_t result, AuthType authType,
        int32_t lockoutDuration, int32_t remainAttempts);
    void ReportWidgetTip(int32_t tipType, AuthType authType, std::vector<uint8_t> tipInfo);

    // others
    void SetPinSubType(const PinSubType &subType);
    void SetSensorInfo(const std::string &info);
    void Reset();
    void ForceStopAuth();

    // extra info
    void SetChallenge(const std::vector<uint8_t> &challenge);
    void SetCallingBundleName(const std::string &callingBundleName);

private:
    WidgetClient() = default;
    void SendCommand(const WidgetCommand &command);
    bool GetAuthTypeList(const WidgetNotice &notice, std::vector<AuthType> &authTypeList);
    bool IsValidNoticeType(const WidgetNotice &notice);

private:
    std::shared_ptr<WidgetScheduleNode> schedule_ {nullptr};
    uint64_t widgetContextId_ {0};
    WidgetParam widgetParam_ {};
    std::vector<AuthType> authTypeList_ {};
    sptr<WidgetCallbackInterface> widgetCallback_ {nullptr};
    std::string pinSubType_ {""};
    std::string sensorInfo_ {""};
    uint32_t authTokenId_ {0};
    std::vector<uint8_t> challenge_ {};
    std::string callingBundleName_ {""};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_CLIENT_H