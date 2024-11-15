/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "keyguard_status_listener_test.h"
#include "keyguard_status_listener.h"

#include "gtest/gtest.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void KeyguardStatusListenerTest::SetUpTestCase()
{
}

void KeyguardStatusListenerTest::TearDownTestCase()
{
}

void KeyguardStatusListenerTest::SetUp()
{
}

void KeyguardStatusListenerTest::TearDown()
{
}

HWTEST_F(KeyguardStatusListenerTest, KeyguardStatusListenerTestRegisterListener, TestSize.Level0)
{
    ResultCode result = KeyguardStatusListenerManager::GetInstance().RegisterCommonEventListener();
    EXPECT_EQ(result, SUCCESS);
    result = KeyguardStatusListenerManager::GetInstance().RegisterCommonEventListener();
    EXPECT_NO_THROW(KeyguardStatusListenerManager::GetInstance().RegisterKeyguardStatusSwitchCallback());
    EXPECT_NO_THROW(KeyguardStatusListenerManager::GetInstance().RegisterKeyguardStatusSwitchCallback());
    EXPECT_NO_THROW(KeyguardStatusListenerManager::GetInstance().UnRegisterKeyguardStatusSwitchCallback());
    EXPECT_NO_THROW(KeyguardStatusListenerManager::GetInstance().UnRegisterKeyguardStatusSwitchCallback());
    result = KeyguardStatusListenerManager::GetInstance().UnRegisterCommonEventListener();
    EXPECT_EQ(result, SUCCESS);
    result = KeyguardStatusListenerManager::GetInstance().UnRegisterCommonEventListener();
}

HWTEST_F(KeyguardStatusListenerTest, KeyguardStatusListenerTestOnReceiveEvent, TestSize.Level0)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);

    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriber = std::make_shared<KeyguardStatusListener>(subscribeInfo);
    EventFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    EventFwk::CommonEventData data(want);
    EXPECT_NO_THROW(subscriber->OnReceiveEvent(data));
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    EventFwk::CommonEventData data1(want);
    EXPECT_NO_THROW(subscriber->OnReceiveEvent(data1));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS