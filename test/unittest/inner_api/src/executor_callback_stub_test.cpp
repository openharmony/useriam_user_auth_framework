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

#include "executor_callback_stub_test.h"

#include "message_parcel.h"

#include "iam_ptr.h"
#include "mock_executor_callback_service.h"
#include "mock_executor_messenger_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ExecutorCallbackStubTest::SetUpTestCase()
{
}

void ExecutorCallbackStubTest::TearDownTestCase()
{
}

void ExecutorCallbackStubTest::SetUp()
{
}

void ExecutorCallbackStubTest::TearDown()
{
}

HWTEST_F(ExecutorCallbackStubTest, TestOnMessengerReadyStub_001, TestSize.Level0)
{
    sptr<MockExecutorMessengerService> messenger = new MockExecutorMessengerService();
    EXPECT_NE(messenger, nullptr);
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIdList;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = ExecutorCallbackInterface::ON_MESSENGER_READY;

    EXPECT_TRUE(data.WriteInterfaceToken(ExecutorCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteRemoteObject(messenger->AsObject()));
    EXPECT_TRUE(data.WriteUInt8Vector(publicKey));
    EXPECT_TRUE(data.WriteUInt64Vector(templateIdList));

    auto service = Common::MakeShared<MockExecutorCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnMessengerReady(_, _, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(ExecutorCallbackStubTest, TestOnBeginExecuteStub_001, TestSize.Level0)
{
    uint64_t scheduleId = 231527;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> command;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = ExecutorCallbackInterface::ON_BEGIN_EXECUTE;

    EXPECT_TRUE(data.WriteInterfaceToken(ExecutorCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(scheduleId));
    EXPECT_TRUE(data.WriteUInt8Vector(publicKey));
    EXPECT_TRUE(data.WriteUInt8Vector(command));

    auto service = Common::MakeShared<MockExecutorCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnBeginExecute(_, _, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(ExecutorCallbackStubTest, TestOnEndExecuteStub_001, TestSize.Level0)
{
    uint64_t scheduleId = 231527;
    std::vector<uint8_t> command;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = ExecutorCallbackInterface::ON_END_EXECUTE;

    EXPECT_TRUE(data.WriteInterfaceToken(ExecutorCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(scheduleId));
    EXPECT_TRUE(data.WriteUInt8Vector(command));

    auto service = Common::MakeShared<MockExecutorCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnEndExecute(_, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(ExecutorCallbackStubTest, TestOnSetPropertyStub_001, TestSize.Level0)
{
    std::vector<uint8_t> properties;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = ExecutorCallbackInterface::ON_SET_PROPERTY;

    EXPECT_TRUE(data.WriteInterfaceToken(ExecutorCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUInt8Vector(properties));

    auto service = Common::MakeShared<MockExecutorCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnSetProperty(_)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(ExecutorCallbackStubTest, TestOnGetPropertyStub_001, TestSize.Level0)
{
    std::vector<uint8_t> condition;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = ExecutorCallbackInterface::ON_GET_PROPERTY;

    EXPECT_TRUE(data.WriteInterfaceToken(ExecutorCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUInt8Vector(condition));

    auto service = Common::MakeShared<MockExecutorCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnGetProperty(_, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
