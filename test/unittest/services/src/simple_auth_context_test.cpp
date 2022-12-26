/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "simple_auth_context.h"

#include <future>

#include "mock_authentication.h"
#include "mock_context.h"
#include "mock_resource_node.h"
#include "mock_schedule_node.h"
#include "schedule_node_impl.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SimpleAuthContextTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void SimpleAuthContextTest::SetUpTestCase()
{
}

void SimpleAuthContextTest::TearDownTestCase()
{
}

void SimpleAuthContextTest::SetUp()
{
}

void SimpleAuthContextTest::TearDown()
{
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_NullHdi, TestSize.Level0)
{
    const uint64_t testContestId = 2;
    const int32_t testResultCode = 7;
    const auto finalResult = Common::MakeShared<Attributes>();
    ASSERT_NE(finalResult, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _)).Times(Exactly(1));
    // Error: auth is null
    std::shared_ptr<Authentication> auth = nullptr;

    auto oriContext = Common::MakeShared<SimpleAuthContext>(testContestId, auth, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<Context> context = oriContext;
    std::shared_ptr<ScheduleNodeCallback> nodeCallback = oriContext;

    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), false);
    nodeCallback->OnScheduleStoped(testResultCode, finalResult);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_NullCallback, TestSize.Level0)
{
    const uint64_t testContestId = 2;
    const ExecutorRole testRole = static_cast<ExecutorRole>(3);
    const int32_t testModuleType = 4;
    const std::vector<uint8_t> testAcquireMsg = {4, 5, 6};
    const int32_t testResultCode = 7;
    const auto finalResult = Common::MakeShared<Attributes>();
    ASSERT_NE(finalResult, nullptr);

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    // Error: contextCallback is null
    std::shared_ptr<ContextCallback> contextCallback = nullptr;

    auto oriContext = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<ScheduleNodeCallback> nodeCallback = oriContext;

    nodeCallback->OnScheduleStarted();
    nodeCallback->OnScheduleProcessed(testRole, testModuleType, testAcquireMsg);
    nodeCallback->OnScheduleStoped(testResultCode, finalResult);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_BasicInfo, TestSize.Level0)
{
    const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    auto oriContext = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<Context> context = oriContext;

    ASSERT_EQ(context->GetContextId(), testContestId);
    ASSERT_EQ(context->GetContextType(), CONTEXT_SIMPLE_AUTH);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Start_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, GetLatestError()).Times(1);
    EXPECT_CALL(*mockAuth, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: process authentication start fail
            return false;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Start_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: scheduleNodeList size = 0
            return true;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Start_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: scheduleNodeList size = 2
            scheduleList.push_back(Common::MakeShared<MockScheduleNode>());
            scheduleList.push_back(Common::MakeShared<MockScheduleNode>());
            return true;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Start_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: schedule node start fail
            auto scheduleNode = Common::MakeShared<MockScheduleNode>();
            EXPECT_CALL(*scheduleNode, StartSchedule()).Times(Exactly(1)).WillOnce(Return(false));
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Start_005, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const uint64_t testScheduleId = 3;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Success
            EXPECT_EQ(scheduleList.size(), 0U);
            auto scheduleNode = Common::MakeShared<MockScheduleNode>();
            EXPECT_CALL(*scheduleNode, StartSchedule()).Times(Exactly(1)).WillOnce(Return(true));
            EXPECT_CALL(*scheduleNode, GetScheduleId()).Times(Exactly(2)).WillRepeatedly(Return(testScheduleId));
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), true);
    ASSERT_EQ(context->Start(), false);
    auto node = context->GetScheduleNode(testScheduleId);
    ASSERT_NE(node, nullptr);
    node = context->GetScheduleNode(testScheduleId + 1);
    ASSERT_EQ(node, nullptr);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Stop_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, GetLatestError()).Times(1);
    EXPECT_CALL(*mockAuth, Cancel()).Times(Exactly(1)).WillOnce([]() {
        // Error: authentication cancel fail
        return false;
    });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Stop(), false);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Stop_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Cancel()).Times(Exactly(1)).WillOnce([]() { return true; });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Stop_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Start(_, _)).Times(1);
    ON_CALL(*mockAuth, Start)
        .WillByDefault(
            [](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                std::shared_ptr<ScheduleNodeCallback> callback) {
                scheduleList.push_back(nullptr);
                return true;
            }
        );
    EXPECT_CALL(*mockAuth, Cancel()).Times(Exactly(1)).WillOnce([]() {
        return true;
    });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_Stop_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Start(_, _)).Times(1);
    ON_CALL(*mockAuth, Start)
        .WillByDefault(
            [](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                std::shared_ptr<ScheduleNodeCallback> callback) {
                auto scheduleNode = Common::MakeShared<MockScheduleNode>();
                EXPECT_NE(scheduleNode, nullptr);
                EXPECT_CALL(*scheduleNode, StartSchedule()).Times(1);
                EXPECT_CALL(*scheduleNode, StopSchedule()).Times(1);
                scheduleList.push_back(scheduleNode);
                return true;
            }
        );
    EXPECT_CALL(*mockAuth, GetLatestError()).Times(1);
    EXPECT_CALL(*mockAuth, Cancel()).Times(Exactly(1)).WillOnce([]() {
        return false;
    });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), false);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_OnScheduleStarted, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    nodeCallback->OnScheduleStarted();
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_OnScheduleProcessed, TestSize.Level0)
{
    EXPECT_EQ(0, 0);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_OnScheduleStoped_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = 7;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) { EXPECT_EQ(resultCode, testResultCode); });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: result is null when testResultCode is not success
    std::shared_ptr<Attributes> result = nullptr;
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_OnScheduleStoped_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: result is null when testResultCode is success
    std::shared_ptr<Attributes> result = nullptr;
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_OnScheduleStoped_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: ATTR_RESULT_CODE is not set
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_OnScheduleStoped_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, GetLatestError()).Times(1);
    EXPECT_CALL(*mockAuth, Update(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, Authentication::AuthResultInfo &resultInfo) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            return false;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: auth_->Update return false
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret, true);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_OnScheduleStoped_005, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};
    static const int32_t testResultCode = 7;
    static const int32_t testFreezingTime = 8;
    static const int32_t testRemainTimes = 9;
    static const std::vector<uint8_t> testSignature = {10, 11, 12, 13};

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Update(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, Authentication::AuthResultInfo &resultInfo) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            resultInfo.result = testResultCode;
            resultInfo.freezingTime = testFreezingTime;
            resultInfo.remainTimes = testRemainTimes;
            resultInfo.token = testSignature;
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, testResultCode);
            uint32_t attrResultCode;
            int32_t freezingTime;
            int32_t remainTimes;
            vector<uint8_t> signature;
            bool ret = finalResult.GetUint32Value(Attributes::ATTR_RESULT_CODE, attrResultCode);
            EXPECT_EQ(ret, true);
            ret = finalResult.GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime);
            EXPECT_EQ(ret, true);
            ret = finalResult.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes);
            EXPECT_EQ(ret, true);
            ret = finalResult.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, signature);
            EXPECT_EQ(ret, true);

            EXPECT_EQ(resultCode, testResultCode);
            EXPECT_EQ(freezingTime, testFreezingTime);
            EXPECT_EQ(remainTimes, testRemainTimes);
            EXPECT_EQ(signature, testSignature);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Success
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret, true);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_OnScheduleStoped_006, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};
    static const int32_t testResultCode = 7;
    static const int32_t testFreezingTime = 8;
    static const int32_t testRemainTimes = 9;
    static const std::vector<uint8_t> testSignature = {10, 11, 12, 13};

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Update(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, Authentication::AuthResultInfo &resultInfo) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            resultInfo.result = testResultCode;
            resultInfo.freezingTime = testFreezingTime;
            resultInfo.remainTimes = testRemainTimes;
            resultInfo.token = testSignature;
            resultInfo.rootSecret = {1, 2, 3, 4};
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _)).Times(1);

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<SimpleAuthContext>(testContestId, mockAuth, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Success
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret, true);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(SimpleAuthContextTest, SimpleAuthContextTest_ContextFree, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockAuthentication> mockAuth = Common::MakeShared<MockAuthentication>();
    ASSERT_NE(mockAuth, nullptr);
    EXPECT_CALL(*mockAuth, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            EXPECT_EQ(scheduleList.size(), 0U);
            auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
            auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
            builder->SetScheduleCallback(callback);
            auto scheduleNode = builder->Build();
            EXPECT_NE(scheduleNode, nullptr);
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    std::promise<void> promise;
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([&promise](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
            promise.set_value();
        });

    std::weak_ptr<Context> weakContext;
    {
        std::shared_ptr<Context> context = Common::MakeShared<SimpleAuthContext>(testContestId,
            mockAuth, contextCallback);
        ASSERT_NE(context, nullptr);
        weakContext = context;
        context->Start();
        promise.get_future().get();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    ASSERT_EQ(weakContext.lock(), nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
