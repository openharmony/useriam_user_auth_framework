/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "context_appstate_observer_test.h"

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "app_state_data.h"
#include "context_appstate_observer.h"
#include "mock_context.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace std;
using namespace testing;
using namespace testing::ext;
void ContextAppStateObserverTest::SetUpTestCase()
{
}

void ContextAppStateObserverTest::TearDownTestCase()
{
}

void ContextAppStateObserverTest::SetUp()
{
}

void ContextAppStateObserverTest::TearDown()
{
}

HWTEST_F(ContextAppStateObserverTest, SubscribeAppStateTest_001, TestSize.Level0)
{
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    uint64_t contextId = 1;
    EXPECT_CALL(*contextCallback, GetCallerName())
        .WillRepeatedly([]() {
                return "com.homs.settings";
            }
        );
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    appStateObserverManager->SubscribeAppState(contextCallback, contextId);
    appStateObserverManager->UnSubscribeAppState();
}

HWTEST_F(ContextAppStateObserverTest, SubscribeAppStateTest_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    appStateObserverManager->SubscribeAppState(nullptr, contextId);
}

HWTEST_F(ContextAppStateObserverTest, SubscribeAppStateTest_003, TestSize.Level0)
{
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    uint64_t contextId = 1;
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    appStateObserverManager->SubscribeAppState(contextCallback, contextId);
}

HWTEST_F(ContextAppStateObserverTest, UnSubscribeAppStateTest_001, TestSize.Level0)
{
    auto appStateObserverManager = Common::MakeShared<ContextAppStateObserverManager>();
    ASSERT_NE(appStateObserverManager, nullptr);
    appStateObserverManager->UnSubscribeAppState();
}

HWTEST_F(ContextAppStateObserverTest, OnAppStateChangedTest_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAppStateChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnAppStateChangedTest_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAppStateChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnAppStateChangedTest_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.setting");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAppStateChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnForegroundApplicationChangedTest_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnForegroundApplicationChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnForegroundApplicationChangedTest_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnForegroundApplicationChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnForegroundApplicationChangedTest_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.setting");
    ASSERT_NE(appStateObserver, nullptr);
    AppStateData appStateData;
    appStateData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    appStateData.bundleName = "com.homs.settings";
    appStateObserver->OnForegroundApplicationChanged(appStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnAbilityStateChangedTest_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.setting");
    ASSERT_NE(appStateObserver, nullptr);
    AbilityStateData abilityStateData;
    abilityStateData.abilityState = static_cast<int32_t>(AbilityState::ABILITY_STATE_BACKGROUND);
    abilityStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAbilityStateChanged(abilityStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnAbilityStateChangedTest_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.settings");
    ASSERT_NE(appStateObserver, nullptr);
    AbilityStateData abilityStateData;
    abilityStateData.abilityState = static_cast<int32_t>(AbilityState::ABILITY_STATE_FOREGROUND);
    abilityStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAbilityStateChanged(abilityStateData);
}

HWTEST_F(ContextAppStateObserverTest, OnAbilityStateChangedTest_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    auto appStateObserver = new (std::nothrow) ContextAppStateObserver(contextId, "com.homs.setting");
    ASSERT_NE(appStateObserver, nullptr);
    AbilityStateData abilityStateData;
    abilityStateData.abilityState = static_cast<int32_t>(AbilityState::ABILITY_STATE_BACKGROUND);
    abilityStateData.bundleName = "com.homs.settings";
    appStateObserver->OnAbilityStateChanged(abilityStateData);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
