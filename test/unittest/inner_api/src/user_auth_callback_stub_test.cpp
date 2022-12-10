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

#include "user_auth_callback_stub_test.h"

#include "message_parcel.h"

#include "iam_ptr.h"
#include "mock_user_auth_callback_service.h"
#include "user_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthCallbackStubTest::SetUpTestCase()
{
}

void UserAuthCallbackStubTest::TearDownTestCase()
{
}

void UserAuthCallbackStubTest::SetUp()
{
}

void UserAuthCallbackStubTest::TearDown()
{
}

HWTEST_F(UserAuthCallbackStubTest, TestOnResultStub_001, TestSize.Level0)
{
    int32_t result = 0;
    std::vector<uint8_t> extraInfo = {1, 2, 3, 4};

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterface::USER_AUTH_ON_RESULT;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(result));
    EXPECT_TRUE(data.WriteUInt8Vector(extraInfo));

    auto service = Common::MakeShared<MockUserAuthCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnResult(_, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserAuthCallbackStubTest, TestOnAcquireInfoStub_001, TestSize.Level0)
{
    int32_t module = 10;
    int32_t acquireInfo = 20;
    std::vector<uint8_t> extraInfo = {1, 2, 3, 4};

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterface::USER_AUTH_ACQUIRE_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(module));
    EXPECT_TRUE(data.WriteInt32(acquireInfo));
    EXPECT_TRUE(data.WriteUInt8Vector(extraInfo));

    auto service = Common::MakeShared<MockUserAuthCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnAcquireInfo(_, _, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserAuthCallbackStubTest, TestOnGetExecutorPropertyResultStub_001, TestSize.Level0)
{
    int32_t result = 0;
    std::vector<uint8_t> extraInfo = {1, 2, 3, 4};

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterface::USER_AUTH_GET_EX_PROP;

    EXPECT_TRUE(data.WriteInterfaceToken(GetExecutorPropertyCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(result));
    EXPECT_TRUE(data.WriteUInt8Vector(extraInfo));

    auto service = Common::MakeShared<MockGetExecutorPropertyCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnGetExecutorPropertyResult(_, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserAuthCallbackStubTest, TestOnSetExecutorPropertyResultStub_001, TestSize.Level0)
{
    int32_t result = 0;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterface::USER_AUTH_SET_EX_PROP;

    EXPECT_TRUE(data.WriteInterfaceToken(SetExecutorPropertyCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(result));

    auto service = Common::MakeShared<MockSetExecutorPropertyCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnSetExecutorPropertyResult(_)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
