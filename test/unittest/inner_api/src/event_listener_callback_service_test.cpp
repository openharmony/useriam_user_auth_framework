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

#include "event_listener_callback_service_test.h"

#include "event_listener_callback_service.h"

#include "callback_manager.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void EventListenerCallbackServiceTest::SetUpTestCase()
{
}

void EventListenerCallbackServiceTest::TearDownTestCase()
{
}

void EventListenerCallbackServiceTest::SetUp()
{
}

void EventListenerCallbackServiceTest::TearDown()
{
}

HWTEST_F(EventListenerCallbackServiceTest, GetAuthEventListenerSetTest, TestSize.Level0)
{
    int32_t authType = 1;
    auto manager = &EventListenerCallbackManager::GetInstance();
    auto eventListenerSet = manager->GetAuthEventListenerSet(static_cast<AuthType>(authType));
    EXPECT_EQ(eventListenerSet.size(), 0);
}

HWTEST_F(EventListenerCallbackServiceTest, GetCredEventListenerSetTest, TestSize.Level0)
{
    int32_t authType = 1;
    auto manager = &EventListenerCallbackManager::GetInstance();
    auto eventListenerSet = manager->GetCredEventListenerSet(static_cast<AuthType>(authType));
    EXPECT_EQ(eventListenerSet.size(), 0);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS