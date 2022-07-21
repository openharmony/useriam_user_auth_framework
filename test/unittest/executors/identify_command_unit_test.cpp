/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_ptr.h"
#include "identify_command.h"

#include "executor.h"
#include "mock_iexecutor_messenger.h"

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_USER_AUTH_EXECUTOR

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIAM::Common;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class IdentifyCommandUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IdentifyCommandUnitTest::SetUpTestCase()
{
}

void IdentifyCommandUnitTest::TearDownTestCase()
{
}

void IdentifyCommandUnitTest::SetUp()
{
}

void IdentifyCommandUnitTest::TearDown()
{
}

HWTEST_F(IdentifyCommandUnitTest, IdentifyCommand_OnResultTest_001, TestSize.Level0)
{
    static const uint64_t testScheduleId = 123;
    static const ResultCode testResultCode = static_cast<ResultCode>(456);
    static const std::vector<uint8_t> testExtraInfo = {7, 8, 9};

    auto messenger = MakeShared<MockIExecutorMessenger>();
    ASSERT_NE(messenger, nullptr);
    EXPECT_CALL(*messenger, Finish(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](uint64_t scheduleId, ExecutorRole srcRole, int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(scheduleId, testScheduleId);
            EXPECT_EQ(srcRole, ALL_IN_ONE);
            EXPECT_EQ(resultCode, testResultCode);
            uint32_t attrResultCode;
            EXPECT_EQ(finalResult.GetUint32Value(Attributes::ATTR_RESULT_CODE, attrResultCode), true);
            EXPECT_EQ(attrResultCode, static_cast<uint32_t>(testResultCode));
            std::vector<uint8_t> extraInfo;
            EXPECT_EQ(finalResult.GetUint8ArrayValue(Attributes::ATTR_RESULT, extraInfo), true);
            EXPECT_EQ(extraInfo, testExtraInfo);
            return USERAUTH_SUCCESS;
        });
    auto executor = Common::MakeShared<Executor>(nullptr, nullptr, 3);
    ASSERT_NE(executor, nullptr);
}

HWTEST_F(IdentifyCommandUnitTest, IdentifyCommand_OnResultTest_002, TestSize.Level0)
{
    static const std::vector<uint8_t> testExtraInfo = {7, 8, 9};

    auto messenger = MakeShared<MockIExecutorMessenger>();
    ASSERT_NE(messenger, nullptr);
    EXPECT_CALL(*messenger, Finish(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](uint64_t scheduleId, ExecutorRole srcRole, int32_t resultCode, const Attributes &finalResult) {
            // return error
            return USERAUTH_ERROR;
        });
    auto executor = Common::MakeShared<Executor>(nullptr, nullptr, 3);
    ASSERT_NE(executor, nullptr);
}

HWTEST_F(IdentifyCommandUnitTest, IdentifyCommand_OnResultTest_003, TestSize.Level0)
{
    static const uint64_t testScheduleId = 123;
    static const ResultCode testResultCode = static_cast<ResultCode>(456);
    static const std::vector<uint8_t> testExtraInfo = {};

    auto messenger = MakeShared<MockIExecutorMessenger>();
    ASSERT_NE(messenger, nullptr);
    EXPECT_CALL(*messenger, Finish(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](uint64_t scheduleId, ExecutorRole srcRole, int32_t resultCode, const Attributes &finalResult) {
            EXPECT_EQ(scheduleId, testScheduleId);
            EXPECT_EQ(srcRole, ALL_IN_ONE);
            EXPECT_EQ(resultCode, testResultCode);
            uint32_t attrResultCode;
            EXPECT_EQ(finalResult.GetUint32Value(Attributes::ATTR_RESULT_CODE, attrResultCode), true);
            EXPECT_EQ(attrResultCode, static_cast<uint32_t>(testResultCode));
            std::vector<uint8_t> extraInfo;
            EXPECT_EQ(finalResult.GetUint8ArrayValue(Attributes::ATTR_RESULT, extraInfo), true);
            EXPECT_EQ(extraInfo, testExtraInfo);
            return USERAUTH_SUCCESS;
        });
    auto executor = Common::MakeShared<Executor>(nullptr, nullptr, 3);
    ASSERT_NE(executor, nullptr);
}

HWTEST_F(IdentifyCommandUnitTest, IdentifyCommand_OnResultTest_004, TestSize.Level0)
{
    static const std::vector<uint8_t> testExtraInfo = {};

    auto messenger = MakeShared<MockIExecutorMessenger>();
    ASSERT_NE(messenger, nullptr);
    EXPECT_CALL(*messenger, Finish(_, _, _, _)).Times(Exactly(1));
    auto executor = Common::MakeShared<Executor>(nullptr, nullptr, 3);
    ASSERT_NE(executor, nullptr);
}

HWTEST_F(IdentifyCommandUnitTest, IdentifyCommand_OnAcquireInfoTest_001, TestSize.Level0)
{
    static const uint64_t testScheduleId = 123;
    static const std::vector<uint8_t> testExtraInfo = {7, 8, 9};

    auto messenger = MakeShared<MockIExecutorMessenger>();
    ASSERT_NE(messenger, nullptr);
    EXPECT_CALL(*messenger, SendData(_, _, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
                      const std::shared_ptr<AuthMessage> &msg) {
            EXPECT_EQ(scheduleId, testScheduleId);
            EXPECT_EQ(transNum, static_cast<uint64_t>(1));
            EXPECT_EQ(srcRole, ALL_IN_ONE);
            EXPECT_EQ(dstRole, SCHEDULER);
            EXPECT_NE(msg, nullptr);
            return USERAUTH_SUCCESS;
        });
    auto executor = Common::MakeShared<Executor>(nullptr, nullptr, 3);
    ASSERT_NE(executor, nullptr);
}

HWTEST_F(IdentifyCommandUnitTest, IdentifyCommand_OnAcquireInfoTest_002, TestSize.Level0)
{
    static const std::vector<uint8_t> testExtraInfo = {7, 8, 9};

    auto messenger = MakeShared<MockIExecutorMessenger>();
    ASSERT_NE(messenger, nullptr);
    EXPECT_CALL(*messenger, SendData(_, _, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
                      const std::shared_ptr<AuthMessage> &msg) { return USERAUTH_ERROR; });
    auto executor = Common::MakeShared<Executor>(nullptr, nullptr, 3);
    ASSERT_NE(executor, nullptr);
}

HWTEST_F(IdentifyCommandUnitTest, IdentifyCommand_OnAcquireInfoTest_003, TestSize.Level0)
{
    static const std::vector<uint8_t> testExtraInfo = {7, 8, 9};

    auto messenger = MakeShared<MockIExecutorMessenger>();
    ASSERT_NE(messenger, nullptr);
    EXPECT_CALL(*messenger, SendData(_, _, _, _, _))
        .Times(Exactly(3))
        .WillOnce([](uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
                      const std::shared_ptr<AuthMessage> &msg) {
            EXPECT_EQ(transNum, static_cast<uint64_t>(1));
            return USERAUTH_SUCCESS;
        })
        .WillOnce([](uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
                      const std::shared_ptr<AuthMessage> &msg) {
            EXPECT_EQ(transNum, static_cast<uint64_t>(2));
            return USERAUTH_ERROR;
        })
        .WillOnce([](uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
                      const std::shared_ptr<AuthMessage> &msg) {
            EXPECT_EQ(transNum, static_cast<uint64_t>(3));
            return USERAUTH_SUCCESS;
        });
    auto executor = Common::MakeShared<Executor>(nullptr, nullptr, 3);
    ASSERT_NE(executor, nullptr);
}

HWTEST_F(IdentifyCommandUnitTest, IdentifyCommand_MixTest_003, TestSize.Level0)
{
    static const std::vector<uint8_t> testExtraInfo = {7, 8, 9};

    auto messenger = MakeShared<MockIExecutorMessenger>();
    ASSERT_NE(messenger, nullptr);
    EXPECT_CALL(*messenger, Finish(_, _, _, _)).Times(Exactly(1));
    EXPECT_CALL(*messenger, SendData(_, _, _, _, _))
        .Times(Exactly(3))
        .WillRepeatedly([](uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
                            const std::shared_ptr<AuthMessage> &msg) { return USERAUTH_SUCCESS; });
    auto executor = Common::MakeShared<Executor>(nullptr, nullptr, 3);
    ASSERT_NE(executor, nullptr);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
