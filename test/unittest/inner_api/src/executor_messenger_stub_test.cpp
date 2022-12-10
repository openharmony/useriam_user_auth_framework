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

#include "executor_messenger_stub_test.h"

#include "message_parcel.h"

#include "iam_ptr.h"
#include "mock_executor_messenger_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ExecutorMessengerStubTest::SetUpTestCase()
{
}

void ExecutorMessengerStubTest::TearDownTestCase()
{
}

void ExecutorMessengerStubTest::SetUp()
{
}

void ExecutorMessengerStubTest::TearDown()
{
}

HWTEST_F(ExecutorMessengerStubTest, TestSendDataStub_001, TestSize.Level0)
{
    uint64_t scheduleId = 6598;
    uint64_t transNum = 8784;
    ExecutorRole srcRole = SCHEDULER;
    ExecutorRole dstRole = COLLECTOR;
    std::vector<uint8_t> message = {1, 2, 4, 6};

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = ExecutorMessengerInterface::CO_AUTH_SEND_DATA;

    EXPECT_TRUE(data.WriteInterfaceToken(ExecutorMessengerInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(scheduleId));
    EXPECT_TRUE(data.WriteUint64(transNum));
    EXPECT_TRUE(data.WriteInt32(srcRole));
    EXPECT_TRUE(data.WriteInt32(dstRole));
    EXPECT_TRUE(data.WriteUInt8Vector(message));
    
    auto service = Common::MakeShared<MockExecutorMessengerService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SendData(_, _, _, _, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(ExecutorMessengerStubTest, TestFinishStub_001, TestSize.Level0)
{
    uint64_t scheduleId = 6598;
    ExecutorRole srcRole = SCHEDULER;
    ResultCode resultCode = SUCCESS;
    std::vector<uint8_t> finalResult = {1, 2, 4, 6};

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = ExecutorMessengerInterface::CO_AUTH_FINISH;

    EXPECT_TRUE(data.WriteInterfaceToken(ExecutorMessengerInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(scheduleId));
    EXPECT_TRUE(data.WriteInt32(srcRole));
    EXPECT_TRUE(data.WriteInt32(resultCode));
    EXPECT_TRUE(data.WriteUInt8Vector(finalResult));

    auto service = Common::MakeShared<MockExecutorMessengerService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Finish(_, _, _, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
