/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IAM_ENROLL_CONTEXT_H
#define IAM_ENROLL_CONTEXT_H

#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "iam_common_defines.h"
#include "system_ability_definition.h"
#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using CommonEventSubscriber = OHOS::EventFwk::CommonEventSubscriber;
using CommonEventData = OHOS::EventFwk::CommonEventData;
using CommonEventSubscribeInfo = OHOS::EventFwk::CommonEventSubscribeInfo;

class KeyguardStatusListenerManager {
public:
    KeyguardStatusListenerManager() = default;
    ~KeyguardStatusListenerManager() = default;

    static KeyguardStatusListenerManager &GetInstance();
    ResultCode RegisterCommonEventListener();
    ResultCode UnRegisterCommonEventListener();

private:
    void RegisterKeyguardStatusSwitchCallback();
    void UnRegisterKeyguardStatusSwitchCallback();

    bool isRegisterKeyguardStatus_ = false;
    sptr<SystemAbilityListener> commonEventListener_;
    std::recursive_mutex mutex_;
};

class KeyguardStatusListener : public CommonEventSubscriber {
public:
    explicit KeyguardStatusListener(const CommonEventSubscribeInfo &subscriberInfo)
        : CommonEventSubscriber(subscriberInfo) {}
    ~KeyguardStatusListener() = default;

    void OnReceiveEvent(const CommonEventData &data) override;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_ENROLL_CONTEXT_H
