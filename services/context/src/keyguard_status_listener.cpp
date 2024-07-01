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

#include "keyguard_status_listener.h"

#include "context_appstate_observer.h"
#include "common_event_subscribe_info.h"
#include "iam_logger.h"
#include "matching_skills.h"
#include "singleton.h"
#include "want.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
KeyguardStatusListenerManager &KeyguardStatusListenerManager::GetInstance()
{
    static KeyguardStatusListenerManager instance;
    return instance;
}

void KeyguardStatusListenerManager::RegisterKeyguardStatusSwitchCallback()
{
    IAM_LOGI("start");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);

    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriber = std::make_shared<KeyguardStatusListener>(subscribeInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber)) {
        IAM_LOGE("SubscribeCommonEvent fail");
    }
}

void KeyguardStatusListener::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    IAM_LOGI("OnReceiveEvent %{public}s", action.c_str());

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
        ContextAppStateObserverManager::GetInstance().SetScreenLockState(true);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        ContextAppStateObserverManager::GetInstance().SetScreenLockState(false);
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS