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

#include "auth_event_listener_manager_test.h"
#include "auth_event_listener_manager.h"

#include "gtest/gtest.h"
#include "mock_auth_event_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void AuthEventListenerManagerTest::SetUpTestCase()
{
}

void AuthEventListenerManagerTest::TearDownTestCase()
{
}

void AuthEventListenerManagerTest::SetUp()
{
}

void AuthEventListenerManagerTest::TearDown()
{
}

HWTEST_F(AuthEventListenerManagerTest, AuthEventListenerManagerTestAddAuthSuccessEventListener, TestSize.Level0)
{
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    AuthType authType = AuthType::PIN;
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().AddAuthSuccessEventListener(authType, testCallback));
}

HWTEST_F(AuthEventListenerManagerTest, AuthEventListenerManagerTestRemoveAuthSuccessEventListener, TestSize.Level0)
{
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    AuthType authType = AuthType::PIN;
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RemoveAuthSuccessEventListener(authType, testCallback));
}

HWTEST_F(AuthEventListenerManagerTest, AuthEventListenerManagerTestRemoveDeathRecipient, TestSize.Level0)
{
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    EXPECT_NO_THROW(AuthEventListenerManager::GetInstance().RemoveDeathRecipient(testCallback));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS