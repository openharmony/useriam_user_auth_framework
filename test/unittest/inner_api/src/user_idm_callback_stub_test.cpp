/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
    uint32_t code = IdmCallbackInterfaceCode::IDM_CALLBACK_ON_RESULT;

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
    uint32_t code = IdmCallbackInterfaceCode::IDM_CALLBACK_ON_ACQUIRE_INFO;

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
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = IdmGetCredInfoCallbackInterfaceCode::ON_GET_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(IdmGetCredInfoCallbackInterface::GetDescriptor()));

    auto service = Common::MakeShared<MockIdmGetCredInfoCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnCredentialInfos(_))
        .WillOnce(
            [](const std::vector<CredentialInfo> &credInfoList) {
                EXPECT_EQ(credInfoList.size(), 0);
            }
        );

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserIdmCallbackStubTest, TestOnCredentialInfosStub_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = IdmGetCredInfoCallbackInterfaceCode::ON_GET_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(IdmGetCredInfoCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(1000));

    auto service = Common::MakeShared<MockIdmGetCredInfoCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnCredentialInfos(_))
        .WillOnce(
            [](const std::vector<CredentialInfo> &credInfoList) {
                EXPECT_EQ(credInfoList.size(), 0);
            }
        );

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserIdmCallbackStubTest, TestOnSecureUserInfoStub_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = IdmGetSecureUserInfoCallbackInterfaceCode::ON_GET_SEC_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(IdmGetSecureUserInfoCallbackInterface::GetDescriptor()));
    auto service = Common::MakeShared<MockIdmGetSecureUserInfoCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnSecureUserInfo(_))
        .WillOnce(
            [](const SecUserInfo &secUserInfo) {
                EXPECT_EQ(secUserInfo.secureUid, 0);
                EXPECT_EQ(secUserInfo.enrolledInfo.size(), 0);
            }
        );

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(UserIdmCallbackStubTest, TestOnSecureUserInfoStub_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = IdmGetSecureUserInfoCallbackInterfaceCode::ON_GET_SEC_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(IdmGetSecureUserInfoCallbackInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(20));
    EXPECT_TRUE(data.WriteUint32(1000));

    auto service = Common::MakeShared<MockIdmGetSecureUserInfoCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnSecureUserInfo(_))
        .WillOnce(
            [](const SecUserInfo &secUserInfo) {
                EXPECT_EQ(secUserInfo.secureUid, 0);
                EXPECT_EQ(secUserInfo.enrolledInfo.size(), 0);
            }
        );

    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
