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

#include "executor_messenger_client_test.h"

#include "executor_messenger_client.h"
#include "iam_ptr.h"
#include "mock_executor_messenger_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ExecutorMessengerClientTest::SetUpTestCase()
{
}

void ExecutorMessengerClientTest::TearDownTestCase()
{
}

void ExecutorMessengerClientTest::SetUp()
{
}

void ExecutorMessengerClientTest::TearDown()
{
}

HWTEST_F(ExecutorMessengerClientTest, ExecutorMessengerClientTestSendData001, TestSize.Level0)
{
    uint64_t testScheduleId = 6598;
    ExecutorRole testDstRole = COLLECTOR;
    std::vector<uint8_t> message = {1, 2, 4, 6};
    std::shared_ptr<AuthMessage> testMsg = AuthMessage::As(message);
    EXPECT_NE(testMsg, nullptr);

    sptr<ExecutorMessengerInterface> testMessenger(nullptr);
    auto service = Common::MakeShared<ExecutorMessengerClient>(testMessenger);
    EXPECT_NE(service, nullptr);
    int32_t result = service->SendData(testScheduleId, testDstRole, testMsg);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(ExecutorMessengerClientTest, ExecutorMessengerClientTestSendData002, TestSize.Level0)
{
    uint64_t testScheduleId = 6598;
    ExecutorRole testDstRole = COLLECTOR;
    std::shared_ptr<AuthMessage> testMsg = nullptr;

    sptr<MockExecutorMessengerService> testMessenger(new (std::nothrow) MockExecutorMessengerService());
    EXPECT_NE(testMessenger, nullptr);
    auto service = Common::MakeShared<ExecutorMessengerClient>(testMessenger);
    EXPECT_NE(service, nullptr);
    int32_t result = service->SendData(testScheduleId, testDstRole, testMsg);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(ExecutorMessengerClientTest, ExecutorMessengerClientTestSendData003, TestSize.Level0)
{
    uint64_t testScheduleId = 6598;
    ExecutorRole testDstRole = COLLECTOR;
    std::vector<uint8_t> message = {1, 2, 4, 6};
    std::shared_ptr<AuthMessage> testMsg = AuthMessage::As(message);
    EXPECT_NE(testMsg, nullptr);

    sptr<MockExecutorMessengerService> testMessenger(new (std::nothrow) MockExecutorMessengerService());
    EXPECT_NE(testMessenger, nullptr);
    EXPECT_CALL(*testMessenger, SendData(_, _, _)).Times(1);
    ON_CALL(*testMessenger, SendData)
        .WillByDefault(
            [&testScheduleId, &testDstRole, &message](uint64_t scheduleId, ExecutorRole dstRole,
                const std::vector<uint8_t> &msg) {
                EXPECT_EQ(scheduleId, testScheduleId);
                EXPECT_THAT(msg, ElementsAreArray(message));
                return SUCCESS;
            }
        );
    auto service = Common::MakeShared<ExecutorMessengerClient>(testMessenger);
    EXPECT_NE(service, nullptr);
    int32_t result = service->SendData(testScheduleId, testDstRole, testMsg);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(ExecutorMessengerClientTest, ExecutorMessengerClientTestFinish001, TestSize.Level0)
{
    uint64_t testScheduleId = 6598;
    int32_t testResultCode = FAIL;
    Attributes finalResult;

    sptr<ExecutorMessengerInterface> testMessenger(nullptr);
    auto service = Common::MakeShared<ExecutorMessengerClient>(testMessenger);
    EXPECT_NE(service, nullptr);
    int32_t result = service->Finish(testScheduleId, testResultCode, finalResult);
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(ExecutorMessengerClientTest, ExecutorMessengerClientTestFinish002, TestSize.Level0)
{
    uint64_t testScheduleId = 6598;
    int32_t testResultCode = FAIL;
    Attributes finalResult;

    sptr<MockExecutorMessengerService> testMessenger(new (std::nothrow) MockExecutorMessengerService());
    EXPECT_NE(testMessenger, nullptr);
    EXPECT_CALL(*testMessenger, Finish(_, _, _)).Times(1);
    ON_CALL(*testMessenger, Finish)
        .WillByDefault(
            [&testScheduleId, &testResultCode](uint64_t scheduleId, ResultCode resultCode,
                const std::shared_ptr<Attributes> &finalResult) {
                EXPECT_EQ(scheduleId, testScheduleId);
                EXPECT_EQ(resultCode, testResultCode);
                return SUCCESS;
            }
        );
    auto service = Common::MakeShared<ExecutorMessengerClient>(testMessenger);
    int32_t result = service->Finish(testScheduleId, testResultCode, finalResult);
    EXPECT_EQ(result, SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS