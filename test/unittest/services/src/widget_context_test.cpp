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

#include "widget_context.h"

#include <future>

#include "mock_context.h"

#include "schedule_node_impl.h"
#include "widget_context_callback_impl.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetContextTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void WidgetContextTest::SetUpTestCase()
{
}

void WidgetContextTest::TearDownTestCase()
{
}

void WidgetContextTest::SetUp()
{
}

void WidgetContextTest::TearDown()
{
}

std::shared_ptr<WidgetContext> CreateWidgetContext(uint64_t contextId, ContextFactory::AuthWidgetContextPara para)
{
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    return Common::MakeShared<WidgetContext>(contextId, para, contextCallback);
}

HWTEST_F(WidgetContextTest, WidgetContextTestStart, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_TRUE(widgetContext->Start());
    EXPECT_FALSE(widgetContext->Start());
}

HWTEST_F(WidgetContextTest, WidgetContextTestStop, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_TRUE(widgetContext->Stop());
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetScheduleNode, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetScheduleNode(contextId), nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetLatestError, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetLatestError(), ResultCode::GENERAL_ERROR);
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetContextType, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetContextType(), WIDGET_AUTH_CONTEXT);
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetTokenId, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetTokenId(), (uint32_t)0);
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0, 1};
    para.atl = ATL2;
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);

    std::set<AuthType> authTypeList;
    authTypeList.insert(FACE);
    authTypeList.insert(ALL);
    authTypeList.insert(PIN);
    authTypeList.insert(FINGERPRINT);
    widgetContext->ExecuteAuthList(authTypeList);

    int32_t resultCode = 1;
    int32_t at = 1;
    Attributes finalResult;
    AuthType authType = ALL;
    sptr<IamCallbackInterface> testCallback = new (std::nothrow) WidgetContextCallbackImpl(widgetContext,
        static_cast<int32_t>(authType));
    widgetContext->AuthResult(resultCode, at, finalResult, testCallback);
    EXPECT_NE(testCallback, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    int32_t resultCode = 1;
    int32_t at = 1;
    Attributes finalResult;
    sptr<IamCallbackInterface> task = nullptr;
    widgetContext->AuthResult(resultCode, at, finalResult, task);
    EXPECT_EQ(task, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    ContextFactory::AuthWidgetContextPara::AuthProfile contextPara;
    para.authProfileMap[PIN] = contextPara;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    ContextFactory::AuthWidgetContextPara::AuthProfile authProfile;
    authProfile.sensorInfo = "1";
    para.authProfileMap[AuthType::FINGERPRINT] = authProfile;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestExecuteAuthList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::set<AuthType> authTypeList;
    widgetContext->ExecuteAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsCancel, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->EndAuthAsCancel();
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsNaviPin, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->EndAuthAsNaviPin();
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAuthList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::vector<AuthType> authTypeList;
    widgetContext->StopAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAuthList_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::vector<AuthType> authTypeList = {ALL, PIN, FACE};
    widgetContext->StopAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAuthList_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0, 1};
    para.atl = ATL2;
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::set<AuthType> authTypeList;
    authTypeList.insert(FACE);
    authTypeList.insert(ALL);
    widgetContext->ExecuteAuthList(authTypeList);

    std::vector<AuthType> testTypeList = {ALL, PIN, FACE};
    widgetContext->StopAuthList(testTypeList);
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    AuthType authType = ALL;
    widgetContext->SuccessAuth(authType);
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    AuthType authType = ALL;
    widgetContext->LaunchWidget();
    widgetContext->SuccessAuth(authType);
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0, 1};
    para.atl = ATL2;
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::set<AuthType> authTypeList;
    authTypeList.insert(FACE);
    widgetContext->ExecuteAuthList(authTypeList);
    AuthType authType = ALL;
    widgetContext->SuccessAuth(authType);
    EXPECT_NE(widgetContext, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestExecuteAuthList_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0, 1};
    para.atl = ATL2;
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::set<AuthType> authTypeList;
    authTypeList.insert(FACE);
    widgetContext->ExecuteAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
