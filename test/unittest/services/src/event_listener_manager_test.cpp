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
#include "mock_remote_object.h"

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
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_EQ(AuthEventListenerManager::GetInstance().RegistEventListener(nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RegistEventListener(testCallback));

    EXPECT_EQ(CredChangeEventListenerManager::GetInstance().RegistEventListener(nullptr),
        GENERAL_ERROR);
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RegistEventListener(testCallback));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestUnRegistEventListener, TestSize.Level0)
{
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_EQ(AuthEventListenerManager::GetInstance().UnRegistEventListener(nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().UnRegistEventListener(testCallback));

    EXPECT_EQ(CredChangeEventListenerManager::GetInstance().UnRegistEventListener(nullptr), GENERAL_ERROR);
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().UnRegistEventListener(testCallback));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRemoveDeathRecipient_001, TestSize.Level0)
{
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RemoveDeathRecipient(testCallback));
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RemoveDeathRecipient(nullptr));
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RemoveDeathRecipient(testCallback));
    EXPECT_NO_THROW(CredChangeEventListenerManager::GetInstance().RemoveDeathRecipient(nullptr));
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestRemoveDeathRecipient_002, TestSize.Level0)
{
    auto mockCallbackRemove = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallbackRemove, AsObject())
        .WillOnce(Return(obj))
        .WillRepeatedly(Return(obj));
    
    AuthEventListenerManager& authEventListenerManager = AuthEventListenerManager::GetInstance();
    EXPECT_EQ(authEventListenerManager.RemoveDeathRecipient(mockCallbackRemove), SUCCESS);
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestAddDeathRecipient_001, TestSize.Level0)
{
    auto mockCallbackAdd = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallbackAdd, AsObject())
        .WillOnce(Return(obj))
        .WillRepeatedly(Return(obj));

    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillOnce(Return(false));

    AuthEventListenerManager& authEventListenerManager = AuthEventListenerManager::GetInstance();
    EXPECT_EQ(authEventListenerManager.AddDeathRecipient(&authEventListenerManager, mockCallbackAdd), GENERAL_ERROR);
}

HWTEST_F(EventListenerManagerTest, EventListenerManagerTestAddDeathRecipient_002, TestSize.Level0)
{
    auto mockCallbackAdd = new MockEventListener();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject);
    EXPECT_CALL(*mockCallbackAdd, AsObject())
        .WillOnce(Return(obj))
        .WillRepeatedly(Return(obj));

    EXPECT_CALL(*obj, AddDeathRecipient(_))
        .WillOnce(Return(true));

    AuthEventListenerManager& authEventListenerManager = AuthEventListenerManager::GetInstance();
    EXPECT_EQ(authEventListenerManager.AddDeathRecipient(&authEventListenerManager, mockCallbackAdd), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS