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
    EXPECT_EQ(result, GENERAL_ERROR);
    EXPECT_NO_THROW(KeyguardStatusListenerManager::GetInstance().RegisterKeyguardStatusSwitchCallback());
    EXPECT_NO_THROW(KeyguardStatusListenerManager::GetInstance().UnRegisterKeyguardStatusSwitchCallback());
    result = KeyguardStatusListenerManager::GetInstance().UnRegisterCommonEventListener();
    EXPECT_EQ(result, GENERAL_ERROR);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS