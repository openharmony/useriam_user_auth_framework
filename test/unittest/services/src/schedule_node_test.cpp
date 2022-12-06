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

#include "schedule_node_test.h"

#include "iam_ptr.h"
#include "schedule_node.h"

#include "mock_executor_callback.h"
#include "mock_resource_node.h"
#include "mock_schedule_node_callback.h"
#include "mock_thread_handler.h"
#include "relative_timer.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ScheduleNodeTest::SetUpTestCase()
{
}

void ScheduleNodeTest::TearDownTestCase()
{
}

void ScheduleNodeTest::SetUp()
{
}

void ScheduleNodeTest::TearDown()
{
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeBuilderWithNullptr, TestSize.Level0)
{
    auto builder = ScheduleNode::Builder::New(nullptr, nullptr);
    EXPECT_EQ(builder, nullptr);
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeBuilderOneCollectorFailed, TestSize.Level0)
{
    {
        auto faceCollector = MockResourceNode::CreateWithExecuteIndex(1, FACE, COLLECTOR);
        auto builder = ScheduleNode::Builder::New(faceCollector, faceCollector);
        EXPECT_EQ(builder, nullptr);
    }
    {
        auto faceVerifier = MockResourceNode::CreateWithExecuteIndex(1, FACE, VERIFIER);
        auto builder = ScheduleNode::Builder::New(faceVerifier, faceVerifier);
        EXPECT_EQ(builder, nullptr);
    }

    {
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        EXPECT_EQ(scheduleNode->GetCollectorExecutor().lock(), faceAllInOne);
        EXPECT_EQ(scheduleNode->GetVerifyExecutor().lock(), faceAllInOne);
    }

    {
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto faceVerifier = MockResourceNode::CreateWithExecuteIndex(1, FACE, VERIFIER);
        auto builder = ScheduleNode::Builder::New(faceVerifier, faceAllInOne);
        EXPECT_EQ(builder, nullptr);
    }

    {
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto faceVerifier = MockResourceNode::CreateWithExecuteIndex(1, FACE, VERIFIER);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceVerifier);
        EXPECT_EQ(builder, nullptr);
    }

    {
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto faceCollector = MockResourceNode::CreateWithExecuteIndex(1, FACE, COLLECTOR);
        auto builder = ScheduleNode::Builder::New(faceCollector, faceAllInOne);
        EXPECT_EQ(builder, nullptr);
    }

    {
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto faceCollector = MockResourceNode::CreateWithExecuteIndex(1, FACE, COLLECTOR);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceCollector);
        EXPECT_EQ(builder, nullptr);
    }
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeBuilderOneCollectorSuccess, TestSize.Level0)
{
    {
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        EXPECT_EQ(scheduleNode->GetCollectorExecutor().lock(), faceAllInOne);
        EXPECT_EQ(scheduleNode->GetVerifyExecutor().lock(), faceAllInOne);
    }
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeBuilderTwoExecutorsFailed, TestSize.Level0)
{
    {
        auto faceCollector = MockResourceNode::CreateWithExecuteIndex(1, FACE, COLLECTOR);
        auto builder = ScheduleNode::Builder::New(faceCollector, faceCollector);
        EXPECT_EQ(builder, nullptr);
    }

    {
        auto faceVerifier = MockResourceNode::CreateWithExecuteIndex(1, FACE, VERIFIER);
        auto builder = ScheduleNode::Builder::New(faceVerifier, faceVerifier);
        EXPECT_EQ(builder, nullptr);
    }

    {
        auto faceCollector = MockResourceNode::CreateWithExecuteIndex(1, FACE, COLLECTOR);
        auto faceVerifier = MockResourceNode::CreateWithExecuteIndex(1, FACE, VERIFIER);
        // test paras error
        auto builder = ScheduleNode::Builder::New(faceVerifier, faceCollector);
        EXPECT_EQ(builder, nullptr);
    }

    {
        auto faceCollector = MockResourceNode::CreateWithExecuteIndex(1, FACE, COLLECTOR);
        auto pinVerifier = MockResourceNode::CreateWithExecuteIndex(1, PIN, VERIFIER);
        auto builder = ScheduleNode::Builder::New(faceCollector, pinVerifier);
        EXPECT_EQ(builder, nullptr);
    }
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeBuilderTwoExecutorsSuccess, TestSize.Level0)
{
    {
        auto faceCollector = MockResourceNode::CreateWithExecuteIndex(1, FACE, COLLECTOR);
        auto faceVerifier = MockResourceNode::CreateWithExecuteIndex(1, FACE, VERIFIER);
        auto builder = ScheduleNode::Builder::New(faceCollector, faceVerifier);
        ASSERT_NE(builder, nullptr);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        EXPECT_EQ(scheduleNode->GetCollectorExecutor().lock(), faceCollector);
        EXPECT_EQ(scheduleNode->GetVerifyExecutor().lock(), faceVerifier);
    }
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeBuilderMismatchAuthType, TestSize.Level0)
{
    {
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);
    }

    {
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetAuthType(PIN);
        auto scheduleNode = builder->Build();
        ASSERT_EQ(scheduleNode, nullptr);
    }
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeBuilderOtherParameters, TestSize.Level0)
{
    {
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        std::vector<uint64_t> TEMPLATE_LIST = {1, 2, 3, 4};
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);

        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        builder->SetTemplateIdList(TEMPLATE_LIST);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        EXPECT_EQ(scheduleNode->GetCollectorExecutor().lock(), faceAllInOne);
        EXPECT_EQ(scheduleNode->GetVerifyExecutor().lock(), faceAllInOne);

        EXPECT_EQ(scheduleNode->GetAuthType(), FACE);
        EXPECT_EQ(scheduleNode->GetExecutorMatcher(), EXECUTOR_MATCHER);
        EXPECT_EQ(scheduleNode->GetScheduleId(), SCHEDULE_ID);
        EXPECT_EQ(scheduleNode->GetScheduleMode(), IDENTIFY);
        EXPECT_TRUE(scheduleNode->GetTemplateIdList().has_value());
        EXPECT_THAT(scheduleNode->GetTemplateIdList().value(), ElementsAreArray(TEMPLATE_LIST));
    }
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeBuilderOtherParametersNoTemplate, TestSize.Level0)
{
    {
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(1, FACE, ALL_IN_ONE);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        EXPECT_EQ(scheduleNode->GetCollectorExecutor().lock(), faceAllInOne);
        EXPECT_EQ(scheduleNode->GetVerifyExecutor().lock(), faceAllInOne);

        EXPECT_EQ(scheduleNode->GetAuthType(), FACE);
        EXPECT_EQ(scheduleNode->GetExecutorMatcher(), EXECUTOR_MATCHER);
        EXPECT_EQ(scheduleNode->GetScheduleId(), SCHEDULE_ID);
        EXPECT_EQ(scheduleNode->GetScheduleMode(), IDENTIFY);
        EXPECT_FALSE(scheduleNode->GetTemplateIdList().has_value());
    }
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeStartAllInOneFailed, TestSize.Level0)
{
    MockExecutorCallback executor;
    EXPECT_CALL(executor, OnBeginExecute(_, _, _)).WillOnce(Return(1));

    auto callback = MockScheduleNodeCallback::Create();
    EXPECT_CALL(*callback, OnScheduleStarted()).Times(0);
    EXPECT_CALL(*callback, OnScheduleStoped(_, _)).Times(1);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    {
        constexpr uint32_t EXECUTOR_INDEX = 0xAAAAAAA;
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, FACE, ALL_IN_ONE, executor);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetThreadHandler(handler);
        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        builder->SetScheduleCallback(callback);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        EXPECT_TRUE(scheduleNode->StartSchedule());
        handler->EnsureTask(nullptr);

        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_END);
    }
    handler->EnsureTask(nullptr);
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeStartAllInOneSuccess, TestSize.Level0)
{
    MockExecutorCallback executor;
    EXPECT_CALL(executor, OnBeginExecute(_, _, _)).WillOnce(Return(0));

    auto callback = MockScheduleNodeCallback::Create();
    EXPECT_CALL(*callback, OnScheduleStarted()).Times(1);

    auto handler = ThreadHandler::GetSingleThreadInstance();
    {
        constexpr uint32_t EXECUTOR_INDEX = 0xAAAAAAA;
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, FACE, ALL_IN_ONE, executor);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetThreadHandler(handler);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        builder->SetScheduleCallback(callback);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        EXPECT_TRUE(scheduleNode->StartSchedule());
        handler->EnsureTask(nullptr);
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_AUTH_PROCESSING);
    }
    handler->EnsureTask(nullptr);
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeStartAllInOneSuccessButTimeout, TestSize.Level0)
{
    using namespace std::chrono;

    std::promise<void> ensure;
    MockExecutorCallback executor;
    auto callback = MockScheduleNodeCallback::Create();
    ON_CALL(*callback, OnScheduleStoped(_, _))
        .WillByDefault(
            [&ensure](int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) { ensure.set_value(); });

    auto handler = ThreadHandler::GetSingleThreadInstance();
    {
        constexpr uint32_t EXECUTOR_INDEX = 0xAAAAAAA;
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, FACE, ALL_IN_ONE, executor);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetThreadHandler(handler);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        builder->SetExpiredTime(550);
        builder->SetScheduleCallback(callback);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        InSequence s; // the following four method will be invoke in sequence
        EXPECT_CALL(executor, OnBeginExecute(_, _, _)).WillOnce(Return(0));
        EXPECT_CALL(*callback, OnScheduleStarted()).Times(1);
        EXPECT_CALL(executor, OnEndExecute(_, _)).WillOnce(Return(0));
        EXPECT_CALL(*callback, OnScheduleStoped(TIMEOUT, _)).Times(1);

        const time_point<system_clock> start = system_clock::now();
        EXPECT_TRUE(scheduleNode->StartSchedule());
        handler->EnsureTask(nullptr);
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_AUTH_PROCESSING);
        ensure.get_future().get();
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_END);
        time_point<system_clock> finish = system_clock::now();
        auto cost = duration_cast<milliseconds>(finish - start).count();
        EXPECT_GT(cost, 540);
        EXPECT_LT(cost, 560);
    }
    handler->EnsureTask(nullptr);
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeStartAllInOneSuccessButTimeoutAndEndFail, TestSize.Level0)
{
    using namespace std::chrono;

    std::promise<void> ensure;
    MockExecutorCallback executor;
    auto callback = MockScheduleNodeCallback::Create();
    ON_CALL(*callback, OnScheduleStoped(_, _))
        .WillByDefault(
            [&ensure](int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) { ensure.set_value(); });

    auto handler = ThreadHandler::GetSingleThreadInstance();
    {
        constexpr uint32_t EXECUTOR_INDEX = 0xAAAAAAA;
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        std::vector<uint64_t> TEMPLATE_LIST = {1};
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, FACE, ALL_IN_ONE, executor);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetThreadHandler(handler);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        builder->SetExpiredTime(550);
        builder->SetScheduleCallback(callback);
        auto parameters = Common::MakeShared<Attributes>();
        EXPECT_NE(parameters, nullptr);
        builder->SetParametersAttributes(parameters);
        builder->SetTemplateIdList(TEMPLATE_LIST);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        InSequence s; // the following four method will be invoke in sequence
        EXPECT_CALL(executor, OnBeginExecute(_, _, _)).WillOnce(Return(0));
        EXPECT_CALL(*callback, OnScheduleStarted()).Times(1);
        EXPECT_CALL(executor, OnEndExecute(_, _)).WillOnce(Return(1)); // mock end failed
        EXPECT_CALL(*callback, OnScheduleStoped(TIMEOUT, _)).Times(1);

        const time_point<system_clock> start = system_clock::now();
        EXPECT_TRUE(scheduleNode->StartSchedule());
        handler->EnsureTask(nullptr);
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_AUTH_PROCESSING);
        ensure.get_future().get();
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_END);
        time_point<system_clock> finish = system_clock::now();
        auto cost = duration_cast<milliseconds>(finish - start).count();
        EXPECT_GT(cost, 540);
        EXPECT_LT(cost, 560);
    }
    handler->EnsureTask(nullptr);
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeStartAllInOneSuccessGetResult, TestSize.Level0)
{
    using namespace std::chrono;

    std::promise<void> ensure;
    MockExecutorCallback executor;
    auto callback = MockScheduleNodeCallback::Create();
    ON_CALL(*callback, OnScheduleStoped(_, _))
        .WillByDefault(
            [&ensure](int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) { ensure.set_value(); });

    auto handler = ThreadHandler::GetSingleThreadInstance();
    {
        constexpr uint32_t EXECUTOR_INDEX = 0xAAAAAAA;
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, FACE, ALL_IN_ONE, executor);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetThreadHandler(handler);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        builder->SetScheduleCallback(callback);
        std::shared_ptr<Attributes> parameters = nullptr;
        builder->SetParametersAttributes(parameters);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        InSequence s; // the following four method will be invoke in sequence
        EXPECT_CALL(executor, OnBeginExecute(_, _, _)).WillOnce(Return(0));
        EXPECT_CALL(*callback, OnScheduleStarted()).Times(1);
        EXPECT_CALL(*callback, OnScheduleStoped(SUCCESS, _)).Times(1);

        const time_point<system_clock> start = system_clock::now();

        // return success after 550ms
        RelativeTimer::GetInstance().Register([&scheduleNode]() { scheduleNode->ContinueSchedule(SUCCESS, nullptr); },
            550);

        EXPECT_TRUE(scheduleNode->StartSchedule());
        handler->EnsureTask(nullptr);
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_AUTH_PROCESSING);
        ensure.get_future().get();
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_END);
        time_point<system_clock> finish = system_clock::now();
        auto cost = duration_cast<milliseconds>(finish - start).count();
        EXPECT_GT(cost, 540);
        EXPECT_LT(cost, 560);
    }
    handler->EnsureTask(nullptr);
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeStartAllInOneUserStop, TestSize.Level0)
{
    using namespace std::chrono;

    std::promise<void> ensure;
    MockExecutorCallback executor;
    auto callback = MockScheduleNodeCallback::Create();
    ON_CALL(*callback, OnScheduleStoped(_, _))
        .WillByDefault(
            [&ensure](int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) { ensure.set_value(); });

    auto handler = ThreadHandler::GetSingleThreadInstance();
    {
        constexpr uint32_t EXECUTOR_INDEX = 0xAAAAAAA;
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, FACE, ALL_IN_ONE, executor);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetThreadHandler(handler);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        builder->SetScheduleCallback(callback);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        InSequence s; // the following four method will be invoke in sequence
        EXPECT_CALL(executor, OnBeginExecute(_, _, _)).WillOnce(Return(0));
        EXPECT_CALL(*callback, OnScheduleStarted()).Times(1);
        EXPECT_CALL(executor, OnEndExecute(_, _)).WillOnce(Return(0));
        EXPECT_CALL(*callback, OnScheduleStoped(CANCELED, _)).Times(1);

        const time_point<system_clock> start = system_clock::now();

        // stop schedule after 550ms
        RelativeTimer::GetInstance().Register([&scheduleNode]() { scheduleNode->StopSchedule(); }, 550);

        EXPECT_TRUE(scheduleNode->StartSchedule());
        handler->EnsureTask(nullptr);
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_AUTH_PROCESSING);
        ensure.get_future().get();
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_END);
        time_point<system_clock> finish = system_clock::now();
        auto cost = duration_cast<milliseconds>(finish - start).count();
        EXPECT_GT(cost, 540);
        EXPECT_LT(cost, 560);
    }
    handler->EnsureTask(nullptr);
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeStartAllInOneUserStopAndEndFailed, TestSize.Level0)
{
    using namespace std::chrono;

    std::promise<void> ensure;
    MockExecutorCallback executor;
    auto callback = MockScheduleNodeCallback::Create();
    ON_CALL(*callback, OnScheduleStoped(_, _))
        .WillByDefault(
            [&ensure](int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) { ensure.set_value(); });

    auto handler = ThreadHandler::GetSingleThreadInstance();
    {
        constexpr uint32_t EXECUTOR_INDEX = 0xAAAAAAA;
        constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
        constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
        auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, FACE, ALL_IN_ONE, executor);
        auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
        ASSERT_NE(builder, nullptr);
        builder->SetExecutorMatcher(EXECUTOR_MATCHER);
        builder->SetThreadHandler(handler);
        builder->SetScheduleId(SCHEDULE_ID);
        builder->SetScheduleMode(IDENTIFY);
        builder->SetScheduleCallback(callback);
        builder->SetAccessTokenId(12330);
        builder->SetPinSubType(PIN_SIX);

        auto scheduleNode = builder->Build();
        ASSERT_NE(scheduleNode, nullptr);

        InSequence s; // the following four method will be invoke in sequence
        EXPECT_CALL(executor, OnBeginExecute(_, _, _)).WillOnce(Return(0));
        EXPECT_CALL(*callback, OnScheduleStarted()).Times(1);
        EXPECT_CALL(executor, OnEndExecute(_, _)).WillOnce(Return(1)); // Mock end failed
        EXPECT_CALL(*callback, OnScheduleStoped(CANCELED, _)).Times(1);

        const time_point<system_clock> start = system_clock::now();

        // stop schedule after 550ms
        RelativeTimer::GetInstance().Register([&scheduleNode]() { scheduleNode->StopSchedule(); }, 550);

        EXPECT_TRUE(scheduleNode->StartSchedule());
        handler->EnsureTask(nullptr);
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_AUTH_PROCESSING);
        ensure.get_future().get();
        EXPECT_EQ(scheduleNode->GetCurrentScheduleState(), ScheduleNode::S_END);
        time_point<system_clock> finish = system_clock::now();
        auto cost = duration_cast<milliseconds>(finish - start).count();
        EXPECT_GT(cost, 540);
        EXPECT_LT(cost, 560);
    }
    handler->EnsureTask(nullptr);
}

HWTEST_F(ScheduleNodeTest, ScheduleNodeTestContinueSchedule, TestSize.Level0)
{
    ExecutorRole testSrcRole = COLLECTOR;
    ExecutorRole testDstRole = COLLECTOR;
    uint64_t testTransNum = 58786;
    std::vector<uint8_t> testMsg;

    constexpr uint32_t EXECUTOR_INDEX = 0xAAAAAAA;
    constexpr uint32_t EXECUTOR_MATCHER = 0xDEEDBEEF;
    constexpr uint32_t SCHEDULE_ID = 0xBEEFABCD;
    MockExecutorCallback executor;
    auto faceAllInOne = MockResourceNode::CreateWithExecuteIndex(EXECUTOR_INDEX, FACE, ALL_IN_ONE, executor);
    auto builder = ScheduleNode::Builder::New(faceAllInOne, faceAllInOne);
    EXPECT_NE(builder, nullptr);
    builder->SetExecutorMatcher(EXECUTOR_MATCHER);
    builder->SetScheduleId(SCHEDULE_ID);
    builder->SetScheduleMode(IDENTIFY);
    std::shared_ptr<MockScheduleNodeCallback> callback = nullptr;
    builder->SetScheduleCallback(callback);

    auto scheduleNode = builder->Build();
    EXPECT_NE(scheduleNode, nullptr);

    EXPECT_FALSE(scheduleNode->ContinueSchedule(testSrcRole, testDstRole, testTransNum, testMsg));
    testDstRole = SCHEDULER;
    scheduleNode = builder->Build();
    EXPECT_NE(scheduleNode, nullptr);
    EXPECT_TRUE(scheduleNode->ContinueSchedule(testSrcRole, testDstRole, testTransNum, testMsg));
    callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnScheduleProcessed(_, _, _)).Times(1);
    builder->SetScheduleCallback(callback);
    builder->SetAuthType(FACE);
    scheduleNode = builder->Build();
    EXPECT_NE(scheduleNode, nullptr);
    EXPECT_TRUE(scheduleNode->ContinueSchedule(testSrcRole, testDstRole, testTransNum, testMsg));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
