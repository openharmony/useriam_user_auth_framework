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

#include "user_idm_callback_stub_test.h"

#include "message_parcel.h"

#include "iam_ptr.h"
#include "mock_user_idm_callback_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmCallbackStubTest::SetUpTestCase()
{
}

void UserIdmCallbackStubTest::TearDownTestCase()
{
}

void UserIdmCallbackStubTest::SetUp()
{
}

void UserIdmCallbackStubTest::TearDown()
{
}

HWTEST_F(UserIdmCallbackStubTest, TestOnResultStub_001, TestSize.Level0)
{
    int32_t result = 0;
    std::vector<uint8_t> extraInfo = {1, 2, 3, 4};

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = IdmCallbackInterface::IDM_CALLBACK_ON_RESULT;

    EXPECT_TRUE(data.WriteInterfaceToken(IdmCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(result));
    EXPECT_TRUE(data.WriteUInt8Vector(extraInfo));

    auto service = Common::MakeShared<MockIdmCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnResult(_, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserIdmCallbackStubTest, TestOnAcquireInfoStub_001, TestSize.Level0)
{
    int32_t module = 10;
    int32_t acquireInfo = 20;
    std::vector<uint8_t> extraInfo = {1, 2, 3, 4};

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = IdmCallbackInterface::IDM_CALLBACK_ON_ACQUIRE_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(IdmCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(module));
    EXPECT_TRUE(data.WriteInt32(acquireInfo));
    EXPECT_TRUE(data.WriteUInt8Vector(extraInfo));

    auto service = Common::MakeShared<MockIdmCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnAcquireInfo(_, _, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserIdmCallbackStubTest, TestOnCredentialInfosStub_001, TestSize.Level0)
{
    uint32_t infoSize = 1;
    uint64_t credentialId = 10;
    AuthType authType = FACE;
    PinSubType subType = PIN_SIX;
    uint64_t templateId = 20;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = IdmGetCredInfoCallbackInterface::ON_GET_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(IdmGetCredInfoCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(infoSize));
    EXPECT_TRUE(data.WriteUint64(credentialId));
    EXPECT_TRUE(data.WriteInt32(authType));
    EXPECT_TRUE(data.WriteInt32(subType));
    EXPECT_TRUE(data.WriteUint64(templateId));

    auto service = Common::MakeShared<MockIdmGetCredInfoCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnCredentialInfos(_, _)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserIdmCallbackStubTest, TestOnSecureUserInfoStub_001, TestSize.Level0)
{
    uint64_t secUid = 10;
    uint32_t infoSize = 1;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = IdmGetSecureUserInfoCallbackInterface::ON_GET_SEC_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(IdmGetSecureUserInfoCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(secUid));
    EXPECT_TRUE(data.WriteUint32(infoSize));

    auto service = Common::MakeShared<MockIdmGetSecureUserInfoCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnSecureUserInfo(_)).Times(1);

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
