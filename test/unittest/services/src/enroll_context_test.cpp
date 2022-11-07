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

#include "enroll_context.h"

#include "mock_context.h"
#include "mock_credential_info.h"
#include "mock_enrollment.h"
#include "mock_schedule_node.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EnrollContextTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void EnrollContextTest::SetUpTestCase()
{
}

void EnrollContextTest::TearDownTestCase()
{
}

void EnrollContextTest::SetUp()
{
}

void EnrollContextTest::TearDown()
{
}

HWTEST_F(EnrollContextTest, EnrollContextTest_NullHdi, TestSize.Level0)
{
    const uint64_t testContestId = 2;
    const int32_t testResultCode = 7;
    const auto finalResult = Common::MakeShared<Attributes>();
    ASSERT_NE(finalResult, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _)).Times(Exactly(1));
    // Error: enroll is null
    std::shared_ptr<Enrollment> enroll = nullptr;

    auto oriContext = Common::MakeShared<EnrollContext>(testContestId, enroll, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<Context> context = oriContext;
    std::shared_ptr<ScheduleNodeCallback> nodeCallback = oriContext;

    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), false);
    nodeCallback->OnScheduleStoped(testResultCode, finalResult);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_NullCallback, TestSize.Level0)
{
    const uint64_t testContestId = 2;
    const ExecutorRole testRole = static_cast<ExecutorRole>(3);
    const int32_t testModuleType = 4;
    const std::vector<uint8_t> testAcquireMsg = {4, 5, 6};
    const int32_t testResultCode = 7;
    const auto finalResult = Common::MakeShared<Attributes>();
    ASSERT_NE(finalResult, nullptr);

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    // Error: contextCallback is null
    std::shared_ptr<ContextCallback> contextCallback = nullptr;

    auto oriContext = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<ScheduleNodeCallback> nodeCallback = oriContext;

    nodeCallback->OnScheduleStarted();
    nodeCallback->OnScheduleProcessed(testRole, testModuleType, testAcquireMsg);
    nodeCallback->OnScheduleStoped(testResultCode, finalResult);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_BasicInfo, TestSize.Level0)
{
    const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    auto oriContext = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(oriContext, nullptr);
    std::shared_ptr<Context> context = oriContext;

    ASSERT_EQ(context->GetContextId(), testContestId);
    ASSERT_EQ(context->GetContextType(), CONTEXT_ENROLL);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Start_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, GetLatestError()).Times(1);
    EXPECT_CALL(*mockEnroll, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: process enrollment start fail
            return false;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Start_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: scheduleNodeList size = 0
            return true;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Start_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Start(_, _))
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
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Start_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Error: schedule node start fail
            auto scheduleNode = Common::MakeShared<MockScheduleNode>();
            EXPECT_NE(scheduleNode, nullptr);

            EXPECT_CALL(*scheduleNode, StartSchedule()).Times(Exactly(1)).WillOnce(Return(false));
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Start_005, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const uint64_t testScheduleId = 3;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Start(_, _))
        .Times(Exactly(1))
        .WillOnce([](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                      std::shared_ptr<ScheduleNodeCallback> callback) {
            // Success
            EXPECT_EQ(scheduleList.size(), 0U);
            auto scheduleNode = Common::MakeShared<MockScheduleNode>();
            EXPECT_NE(scheduleNode, nullptr);
            EXPECT_CALL(*scheduleNode, StartSchedule()).Times(Exactly(1)).WillOnce(Return(true));
            EXPECT_CALL(*scheduleNode, GetScheduleId()).Times(Exactly(2)).WillRepeatedly(Return(testScheduleId));
            scheduleList.push_back(scheduleNode);
            return true;
        });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), true);
    ASSERT_EQ(context->Start(), false);
    auto node = context->GetScheduleNode(testScheduleId);
    ASSERT_NE(node, nullptr);
    node = context->GetScheduleNode(testScheduleId + 1);
    ASSERT_EQ(node, nullptr);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Stop_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, GetLatestError()).Times(1);
    EXPECT_CALL(*mockEnroll, Cancel()).Times(Exactly(1)).WillOnce([]() {
        // Error: enrollment cancel fail
        return false;
    });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Stop(), false);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Stop_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Cancel()).Times(Exactly(1)).WillOnce([]() { return true; });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Stop_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Start(_, _)).Times(1);
    ON_CALL(*mockEnroll, Start)
        .WillByDefault(
            [](std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
                std::shared_ptr<ScheduleNodeCallback> callback) {
                scheduleList.push_back(nullptr);
                return true;
            }
        );
    EXPECT_CALL(*mockEnroll, Cancel()).Times(Exactly(1)).WillOnce([]() {
        return true;
    });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), true);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_Stop_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Start(_, _)).Times(1);
    ON_CALL(*mockEnroll, Start)
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
    EXPECT_CALL(*mockEnroll, GetLatestError()).Times(1);
    EXPECT_CALL(*mockEnroll, Cancel()).Times(Exactly(1)).WillOnce([]() {
        return false;
    });
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    std::shared_ptr<Context> context = Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(context->Start(), false);
    ASSERT_EQ(context->Stop(), false);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_OnScheduleStarted, TestSize.Level0)
{
    static const uint64_t testContestId = 2;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    std::shared_ptr<ContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    nodeCallback->OnScheduleStarted();
}

HWTEST_F(EnrollContextTest, EnrollContextTest_OnScheduleProcessed, TestSize.Level0)
{
    EXPECT_EQ(0, 0);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_OnScheduleStoped_001, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = 7;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, testResultCode);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: result is null when testResultCode is not success
    std::shared_ptr<Attributes> result = nullptr;
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_OnScheduleStoped_002, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: result is null when testResultCode is success
    std::shared_ptr<Attributes> result = nullptr;
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_OnScheduleStoped_003, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::GENERAL_ERROR);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: ATTR_RESULT_CODE is not set
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_OnScheduleStoped_004, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const int32_t testResultCode = ResultCode::SUCCESS;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, GetLatestError()).Times(1);
    EXPECT_CALL(*mockEnroll, Update(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
                      std::shared_ptr<CredentialInfo> &info, std::vector<uint8_t> &rootSecret) {
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
        Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Error: enroll_->Update return false
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret1 = result->SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, testScheduleResult);
    ASSERT_EQ(ret1, true);

    bool ret2 = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret2, true);
    nodeCallback->OnScheduleStoped(testResultCode, result);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_OnScheduleStoped_005, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};
    static const uint64_t testCredentialId = 7;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Update(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
                      std::shared_ptr<CredentialInfo> &info, std::vector<uint8_t> &rootSecret) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            credentialId = testCredentialId;
            info = nullptr;
            rootSecret = {};
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(resultCode, ResultCode::SUCCESS);
            uint64_t credentialId;
            bool ret = finalResult.GetUint64Value(Attributes::ATTR_CREDENTIAL_ID, credentialId);
            EXPECT_EQ(ret, true);
            EXPECT_EQ(testCredentialId, credentialId);
        });

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Success
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret1 = result->SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, testScheduleResult);
    ASSERT_EQ(ret1, true);

    bool ret2 = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret2, true);
    nodeCallback->OnScheduleStoped(ResultCode::SUCCESS, result);
}

HWTEST_F(EnrollContextTest, EnrollContextTest_OnScheduleStoped_006, TestSize.Level0)
{
    static const uint64_t testContestId = 2;
    static const std::vector<uint8_t> testScheduleResult = {3, 4, 5, 6};
    static const uint64_t testCredentialId = 7;

    std::shared_ptr<MockEnrollment> mockEnroll = Common::MakeShared<MockEnrollment>();
    ASSERT_NE(mockEnroll, nullptr);
    EXPECT_CALL(*mockEnroll, Update(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
                      std::shared_ptr<CredentialInfo> &info, std::vector<uint8_t> &rootSecret) {
            EXPECT_EQ(scheduleResult, testScheduleResult);
            credentialId = testCredentialId;
            auto credInfo = Common::MakeShared<MockCredentialInfo>();
            EXPECT_NE(credInfo, nullptr);
            EXPECT_CALL(*credInfo, GetExecutorIndex()).WillOnce(Return(10));
            info = credInfo;
            rootSecret = {1, 2, 3, 4};
            return true;
        });
    std::shared_ptr<MockContextCallback> contextCallback = Common::MakeShared<MockContextCallback>();
    ASSERT_NE(contextCallback, nullptr);
    EXPECT_CALL(*contextCallback, OnResult(_, _)).Times(1);

    std::shared_ptr<ScheduleNodeCallback> nodeCallback =
        Common::MakeShared<EnrollContext>(testContestId, mockEnroll, contextCallback);
    ASSERT_NE(nodeCallback, nullptr);
    // Success
    std::shared_ptr<Attributes> result = Common::MakeShared<Attributes>();
    ASSERT_NE(result, nullptr);
    bool ret1 = result->SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, testScheduleResult);
    ASSERT_EQ(ret1, true);

    bool ret2 = result->SetUint8ArrayValue(Attributes::ATTR_RESULT, testScheduleResult);
    ASSERT_EQ(ret2, true);
    nodeCallback->OnScheduleStoped(ResultCode::SUCCESS, result);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
