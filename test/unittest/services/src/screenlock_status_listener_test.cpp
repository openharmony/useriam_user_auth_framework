/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "screenlock_status_listener_test.h"

#include "screenlock_status_listener.h"

#include "gtest/gtest.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ScreenlockStatusListenerTest::SetUpTestCase()
{
}

void ScreenlockStatusListenerTest::TearDownTestCase()
{
}

void ScreenlockStatusListenerTest::SetUp()
{
}

void ScreenlockStatusListenerTest::TearDown()
{
}

HWTEST_F(ScreenlockStatusListenerTest, RegisterCommonEventListenerTest, TestSize.Level0)
{
    ResultCode result = ScreenlockStatusListenerManager::GetInstance().RegisterCommonEventListener();
    EXPECT_EQ(result, SUCCESS);
    result = ScreenlockStatusListenerManager::GetInstance().RegisterCommonEventListener();
    EXPECT_NO_THROW(ScreenlockStatusListenerManager::GetInstance().RegisterScreenLockedCallback());
    EXPECT_NO_THROW(ScreenlockStatusListenerManager::GetInstance().RegisterScreenLockedCallback());
    EXPECT_NO_THROW(ScreenlockStatusListenerManager::GetInstance().UnRegisterScreenLockedCallback());
    EXPECT_NO_THROW(ScreenlockStatusListenerManager::GetInstance().UnRegisterScreenLockedCallback());
}

HWTEST_F(ScreenlockStatusListenerTest, SyncScreenlockStatusTest, TestSize.Level0)
{
    EXPECT_NO_THROW(ScreenlockStatusListenerManager::GetInstance().SyncScreenlockStatus());
}

HWTEST_F(ScreenlockStatusListenerTest, ScreenlockStatusListenerTestOnReceiveEvent, TestSize.Level0)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);

    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriber = std::make_shared<ScreenlockStatusListener>(subscribeInfo);
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