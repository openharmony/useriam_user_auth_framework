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
#include "relative_timer.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
auto &timer = RelativeTimer::GetInstance();
}
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
    return Common::MakeShared<WidgetContext>(contextId, para, contextCallback, nullptr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestStart, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_TRUE(widgetContext->Start());
    EXPECT_FALSE(widgetContext->Start());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStop, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_TRUE(widgetContext->Stop());
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetScheduleNode, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetScheduleNode(contextId), nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetLatestError, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetLatestError(), ResultCode::GENERAL_ERROR);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetContextType, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetContextType(), WIDGET_AUTH_CONTEXT);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetTokenId, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_EQ(widgetContext->GetTokenId(), (uint32_t)0);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    widgetContext->AuthResult(ResultCode::SUCCESS, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
    widgetContext->AuthResult(ResultCode::SUCCESS, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
    finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 1);
    widgetContext->AuthResult(ResultCode::SUCCESS, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
    finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 1);
    widgetContext->AuthResult(ResultCode::SUCCESS, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0005, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 1);
    finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 1);
    widgetContext->AuthResult(ResultCode::GENERAL_ERROR, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0006, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    finalResult.SetInt32Value(Attributes::ATTR_AUTH_TYPE, PIN);
    widgetContext->AuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0007, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    std::vector<uint8_t> token = {1, 1};
    finalResult.SetInt32Value(Attributes::ATTR_AUTH_TYPE, PIN);
    finalResult.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    widgetContext->AuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthResult_0008, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->Start());
    Attributes finalResult;
    std::vector<uint8_t> token = {1, 1};
    finalResult.SetInt32Value(Attributes::ATTR_AUTH_TYPE, PIN);
    finalResult.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    finalResult.SetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, 1);
    widgetContext->AuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, 1, finalResult);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    ContextFactory::AuthProfile contextPara;
    para.authProfileMap[PIN] = contextPara;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestLaunchWidget_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    ContextFactory::AuthProfile authProfile;
    authProfile.sensorInfo = "1";
    para.authProfileMap[AuthType::FINGERPRINT] = authProfile;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->LaunchWidget();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsCancel_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->EndAuthAsCancel();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsCancel_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->SetLatestError(COMPLEXITY_CHECK_FAILED);
    widgetContext->EndAuthAsCancel();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsNaviPin, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->EndAuthAsNaviPin();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestEndAuthAsWidgetParaInvalid, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->EndAuthAsWidgetParaInvalid();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAuthList_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::vector<AuthType> authTypeList;
    widgetContext->StopAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestStopAuthList_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    std::vector<AuthType> authTypeList = {ALL, PIN, FACE};
    widgetContext->StopAuthList(authTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
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
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);

    std::vector<AuthType> testTypeList = {ALL, PIN, FACE};
    widgetContext->StopAuthList(testTypeList);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    AuthType authType = ALL;
    widgetContext->SuccessAuth(authType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
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
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
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
    widgetContext->ExecuteAuthList(authTypeList, true, AuthIntent::DEFAULT);
    AuthType authType = ALL;
    widgetContext->SuccessAuth(authType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestSuccessAuth_004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    AuthType authType = ALL;
    widgetContext->SetLatestError(ResultCode::COMPLEXITY_CHECK_FAILED);
    widgetContext->SuccessAuth(authType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestExecuteAuthList_0001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = Common::MakeShared<WidgetContext>(contextId, para, nullptr, nullptr);
    std::set<AuthType> authTypeList;
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestExecuteAuthList_0002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = Common::MakeShared<WidgetContext>(contextId, para, nullptr, nullptr);
    std::set<AuthType> authTypeList;
    authTypeList.insert(AuthType::PIN);
    widgetContext->ExecuteAuthList(authTypeList, true, AuthIntent::DEFAULT);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestExecuteAuthList_0003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.challenge = {0, 1};
    para.atl = AuthTrustLevel::ATL1;
    auto contextCallback = Common::MakeShared<MockContextCallback>();
    auto widgetContext = Common::MakeShared<WidgetContext>(contextId, para, contextCallback, nullptr);
    std::set<AuthType> authTypeList;
    authTypeList.insert(AuthType::PIN);
    widgetContext->ExecuteAuthList(authTypeList, false, AuthIntent::DEFAULT);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReloadInit, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    widgetContext->AuthWidgetReloadInit();
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 1;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = PIN;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 2;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = FINGERPRINT;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 3;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 1;
    AuthType rotateAuthType = FACE;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 2;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 0;
    AuthType rotateAuthType = FACE;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0005, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 3;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 0;
    AuthType rotateAuthType = FACE;
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestAuthWidgetReload_0006, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    uint32_t orientation = 1;
    uint32_t needRotate = 1;
    uint32_t alreadyLoad = 0;
    AuthType rotateAuthType = FACE;
    WidgetCmdParameters widgetCmdParameters;
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.orientation = 3;
    widgetRotatePara.isReload = 0;
    widgetRotatePara.needRotate = 0;
    widgetContext->ProcessRotatePara(widgetCmdParameters, widgetRotatePara);
    widgetContext->AuthWidgetReload(orientation, needRotate, alreadyLoad, rotateAuthType);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcessRotatePara, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    WidgetCmdParameters widgetCmdParameters;
    WidgetContext::WidgetRotatePara widgetRotatePara;
    widgetRotatePara.orientation = 2;
    widgetRotatePara.isReload = 0;
    widgetRotatePara.needRotate = 1;
    widgetContext->ProcessRotatePara(widgetCmdParameters, widgetRotatePara);
    EXPECT_NE(widgetContext, nullptr);
    auto handler = ThreadHandler::GetSingleThreadInstance();
    handler->EnsureTask([]() {});
}

HWTEST_F(WidgetContextTest, WidgetContextTestGetUserId, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    widgetContext->GetUserId();
}

HWTEST_F(WidgetContextTest, WidgetContextTestOnResult, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::shared_ptr<Attributes> scheduleResultAttr = Common::MakeShared<Attributes>();
    EXPECT_NE(scheduleResultAttr, nullptr);
    int32_t resultCode = 2;
    widgetContext->OnResult(resultCode, scheduleResultAttr);
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleFaceOrFingerPrintAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->IsSingleFaceOrFingerPrintAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleFaceOrFingerPrintAuth_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FINGERPRINT);
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->IsSingleFaceOrFingerPrintAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleFaceOrFingerPrintAuth_003, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    para.widgetParam.navigationButtonText = "111";
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(!widgetContext->IsSingleFaceOrFingerPrintAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsSingleFaceOrFingerPrintAuth_004, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    para.authTypeList.push_back(FINGERPRINT);
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(!widgetContext->IsSingleFaceOrFingerPrintAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsNavigationAuth_001, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    para.widgetParam.navigationButtonText = "111";
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(widgetContext->IsNavigationAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestIsNavigationAuth_002, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    para.authTypeList.push_back(FACE);
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_TRUE(!widgetContext->IsNavigationAuth());
}

HWTEST_F(WidgetContextTest, WidgetContextTestSendAuthTipInfo, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    int32_t authType = FACE;
    int32_t tipCode = TIP_CODE_FAIL;
    EXPECT_NO_THROW(widgetContext->SendAuthTipInfo(authType, tipCode));
}

HWTEST_F(WidgetContextTest, WidgetContextTestCaclAuthTipCode, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    EXPECT_EQ(widgetContext->CaclAuthTipCode(ResultCode::TIMEOUT, 0), TIP_CODE_TIMEOUT);
    EXPECT_EQ(widgetContext->CaclAuthTipCode(ResultCode::FAIL, 1), TIP_CODE_TEMPORARILY_LOCKED);
    EXPECT_EQ(widgetContext->CaclAuthTipCode(ResultCode::FAIL, INT32_MAX), TIP_CODE_PERMANENTLY_LOCKED);
    EXPECT_EQ(widgetContext->CaclAuthTipCode(ResultCode::FAIL, -1), TIP_CODE_FAIL);
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthResult, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    const Attributes attribute;
    EXPECT_NO_THROW(widgetContext->ProcAuthResult(ResultCode::SUCCESS, PIN, 0, attribute));
    EXPECT_NO_THROW(widgetContext->ProcAuthResult(ResultCode::COMPLEXITY_CHECK_FAILED, PIN, 0, attribute));
    EXPECT_NO_THROW(widgetContext->ProcAuthResult(ResultCode::FAIL, PIN, 0, attribute));
}

HWTEST_F(WidgetContextTest, WidgetContextTestProcAuthTipInfo, TestSize.Level0)
{
    uint64_t contextId = 1;
    ContextFactory::AuthWidgetContextPara para;
    auto widgetContext = CreateWidgetContext(contextId, para);
    EXPECT_NE(widgetContext, nullptr);
    std::vector<uint8_t> extraInfo;
    EXPECT_NO_THROW(widgetContext->ProcAuthTipInfo(USER_AUTH_TIP_SINGLE_AUTH_RESULT, PIN, extraInfo));
    EXPECT_NO_THROW(widgetContext->ProcAuthTipInfo(0, PIN, extraInfo));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
