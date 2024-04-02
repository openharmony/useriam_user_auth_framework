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
const std::string ACCESS_AUTH_RESPOOL = "ohos.permission.ACCESS_AUTH_RESPOOL";
const std::string ACROSS_LOCAL_ACCOUNTS_EXTENSION = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION";
const std::string MANAGE_LOCAL_ACCOUNTS = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const std::string VIBRATE = "ohos.permission.VIBRATE";
const std::string GET_RUNNING_INFO = "ohos.permission.GET_RUNNING_INFO";
const std::string START_SYSTEM_DIALOG = "ohos.permission.START_SYSTEM_DIALOG";
const std::string RECEIVER_STARTUP_COMPLETED = "ohos.permission.RECEIVER_STARTUP_COMPLETED";
const std::string RUNNING_STATE_OBSERVER = "ohos.permission.RUNNING_STATE_OBSERVER";
const int32_t LOCATION_PERM_NUM = 8;

void ContextAppStateObserverTest::SetUpTestCase()
{
}

void ContextAppStateObserverTest::TearDownTestCase()
{
}

void ContextAppStateObserverTest::SetUp()
{
    MockNativePermission();
}

void ContextAppStateObserverTest::TearDown()
{
}

void ContextAppStateObserverTest::MockNativePermission()
{
    const char *perms[] = {
        ACCESS_AUTH_RESPOOL.c_str(),
        ACROSS_LOCAL_ACCOUNTS_EXTENSION.c_str(),
        MANAGE_LOCAL_ACCOUNTS.c_str(),
        VIBRATE.c_str(),
        GET_RUNNING_INFO.c_str(),
        START_SYSTEM_DIALOG.c_str(),
        RECEIVER_STARTUP_COMPLETED.c_str(),
        RUNNING_STATE_OBSERVER.c_str(),
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = LOCATION_PERM_NUM,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "ContextAppStateObserverTest",
        .aplStr = "system_basic",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId_);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
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
