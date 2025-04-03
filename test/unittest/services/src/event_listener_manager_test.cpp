/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "event_listener_manager_test.h"
#include "event_listener_manager.h"

#include "gtest/gtest.h"
#include "mock_event_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void EventListenerManagerTest::SetUpTestCase()
{
}

void EventListenerManagerTest::TearDownTestCase()
{
}

void EventListenerManagerTest::SetUp()
{
}

void EventListenerManagerTest::TearDown()
{
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRegistEventListener, TestSize.Level0)
{
    std::vector<AuthType> authType = { AuthType::PIN };
    uint32_t tokenId = 1;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_EQ(AuthEventListenerManager::GetInstance().RegistEventListener(authType, tokenId, nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RegistEventListener(authType, tokenId, testCallback));
    AuthEventListenerManager::GetInstance().GetListenerSet(authType[0]);

    EXPECT_EQ(CredChangeEventListenerManager::GetInstance().RegistEventListener(authType, tokenId, nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RegistEventListener(authType, tokenId, testCallback));
    CredChangeEventListenerManager::GetInstance().GetListenerSet(authType[0]);
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestUnRegistEventListener, TestSize.Level0)
{
    uint32_t tokenId = 1;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_EQ(AuthEventListenerManager::GetInstance().UnRegistEventListener(tokenId, nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().UnRegistEventListener(tokenId, testCallback));

    EXPECT_EQ(CredChangeEventListenerManager::GetInstance().UnRegistEventListener(tokenId, nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().UnRegistEventListener(tokenId, testCallback));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestAddEventListener, TestSize.Level0)
{
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    AuthType authType = AuthType::PIN;
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().AddEventListener(authType, testCallback));
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().AddEventListener(authType, testCallback));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRemoveEventListener, TestSize.Level0)
{
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    AuthType authType = AuthType::PIN;
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RemoveEventListener(authType, testCallback));
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RemoveEventListener(authType, testCallback));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRemoveDeathRecipient, TestSize.Level0)
{
    uint32_t tokenId = 0;
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RemoveDeathRecipient(tokenId));
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RemoveDeathRecipient(tokenId));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS