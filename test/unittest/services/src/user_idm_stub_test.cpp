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

#include "user_idm_stub_test.h"

#include "credential_info.h"
#include "iam_common_defines.h"
#include "securec.h"
#include "user_idm_callback_proxy.h"
#include "user_idm_stub.h"

#include "mock_secure_user_info.h"
#include "mock_user_idm_callback.h"
#include "mock_user_idm_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmStubTest::SetUpTestCase()
{
}

void UserIdmStubTest::TearDownTestCase()
{
}

void UserIdmStubTest::SetUp()
{
}

void UserIdmStubTest::TearDown()
{
}

HWTEST_F(UserIdmStubTest, UserIdmStubOpenSessionStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_OPEN_SESSION;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubOpenSessionStub002, TestSize.Level0)
{
    int32_t testUserId = 887436;
    std::vector<uint8_t> testChallenge = {1, 2, 8, 4};

    MockUserIdmService service;
    EXPECT_CALL(service, OpenSession(_, _)).Times(1);
    ON_CALL(service, OpenSession)
        .WillByDefault(
            [&testUserId, &testChallenge](int32_t userId, std::vector<uint8_t> &challenge) {
                EXPECT_EQ(userId, testUserId);
                challenge = testChallenge;
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_OPEN_SESSION;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));

    std::vector<uint8_t> challenge;
    EXPECT_TRUE(reply.ReadUInt8Vector(&challenge));
    EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
}

HWTEST_F(UserIdmStubTest, UserIdmStubCloseSessionStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_CLOSE_SESSION;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubCloseSessionStub002, TestSize.Level0)
{
    int32_t testUserId = 887436;

    MockUserIdmService service;
    EXPECT_CALL(service, CloseSession(_)).Times(1);
    ON_CALL(service, CloseSession)
        .WillByDefault(
            [&testUserId](int32_t userId) {
                EXPECT_EQ(userId, testUserId);
                return;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_CLOSE_SESSION;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubGetCredentialInfoStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_GET_CRED_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubGetCredentialInfoStub002, TestSize.Level0)
{
    int32_t testUserId = 76255;
    AuthType testAuthType = FACE;

    sptr<MockIdmGetCredentialInfoCallback> callback = new (std::nothrow) MockIdmGetCredentialInfoCallback();
    EXPECT_NE(callback, nullptr);
    MockUserIdmService service;
    EXPECT_CALL(service, GetCredentialInfo(_, _, _)).Times(1);
    ON_CALL(service, GetCredentialInfo)
        .WillByDefault(
            [&testUserId, &testAuthType](int32_t userId, AuthType authType,
                const sptr<IdmGetCredInfoCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testAuthType);
                if (callback != nullptr) {
                    std::vector<std::shared_ptr<CredentialInfo>> infoList;
                    callback->OnCredentialInfos(infoList, std::nullopt);
                }
                return SUCCESS;
            }
        );
    EXPECT_CALL(*callback, OnCredentialInfos(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_GET_CRED_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUint32(testAuthType));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));

    int32_t result = FAIL;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserIdmStubTest, UserIdmStubGetSecInfoStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_GET_SEC_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubGetSecInfoStub002, TestSize.Level0)
{
    int32_t testUserId = 87463;

    sptr<MockIdmGetSecureUserInfoCallback> callback = new (std::nothrow) MockIdmGetSecureUserInfoCallback();
    EXPECT_NE(callback, nullptr);
    MockUserIdmService service;
    EXPECT_CALL(service, GetSecInfo(_, _)).Times(1);
    ON_CALL(service, GetSecInfo)
        .WillByDefault(
            [&testUserId](int32_t userId, const sptr<IdmGetSecureUserInfoCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                if (callback != nullptr) {
                    const std::shared_ptr<IdmGetSecureUserInfoCallbackInterface::SecureUserInfo> info;
                    callback->OnSecureUserInfo(info);
                }
                return SUCCESS;
            }
        );
    EXPECT_CALL(*callback, OnSecureUserInfo(_)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_GET_SEC_INFO;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));

    int32_t result = FAIL;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserIdmStubTest, UserIdmStubAddCredentialStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_ADD_CREDENTIAL;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubAddCredentialStub002, TestSize.Level0)
{
    int32_t testUserId = 753662;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = FACE;
    testCredPara.pinType = PIN_SIX;
    testCredPara.token = {2, 4, 6, 8};

    sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    EXPECT_NE(callback, nullptr);
    MockUserIdmService service;
    EXPECT_CALL(service, AddCredential(_, _, _, _)).Times(1);
    ON_CALL(service, AddCredential)
        .WillByDefault(
            [&testUserId, &testCredPara](int32_t userId, const UserIdmInterface::CredentialPara &credPara,
                const sptr<IdmCallbackInterface> &callback, bool isUpdate) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(credPara.authType, testCredPara.authType);
                EXPECT_EQ(credPara.pinType, testCredPara.pinType);
                EXPECT_THAT(credPara.token, ElementsAreArray(testCredPara.token));
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_ADD_CREDENTIAL;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteInt32(testCredPara.authType));
    EXPECT_TRUE(data.WriteInt32(testCredPara.pinType));
    EXPECT_TRUE(data.WriteUInt8Vector(testCredPara.token));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubUpdateCredentialStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_UPDATE_CREDENTIAL;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubUpdateCredentialStub002, TestSize.Level0)
{
    int32_t testUserId = 63526;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = PIN;
    testCredPara.pinType = PIN_SIX;
    testCredPara.token = {1, 2, 4, 6, 8};

    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    EXPECT_NE(callback, nullptr);
    MockUserIdmService service;
    EXPECT_CALL(service, UpdateCredential(_, _, _)).Times(1);
    ON_CALL(service, UpdateCredential)
        .WillByDefault(
            [&testUserId, &testCredPara](int32_t userId, const UserIdmInterface::CredentialPara &credPara,
                const sptr<IdmCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(credPara.authType, testCredPara.authType);
                EXPECT_EQ(credPara.pinType, testCredPara.pinType);
                EXPECT_THAT(credPara.token, ElementsAreArray(testCredPara.token));
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_UPDATE_CREDENTIAL;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteInt32(testCredPara.authType));
    EXPECT_TRUE(data.WriteInt32(testCredPara.pinType));
    EXPECT_TRUE(data.WriteUInt8Vector(testCredPara.token));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubCancelStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_CANCEL;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubCancelStub002, TestSize.Level0)
{
    int32_t testUserId = 725345;

    MockUserIdmService service;
    EXPECT_CALL(service, Cancel(_)).Times(1);
    ON_CALL(service, Cancel)
        .WillByDefault(
            [&testUserId](int32_t userId) {
                EXPECT_EQ(userId, testUserId);
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_CANCEL;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));

    int32_t result = FAIL;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserIdmStubTest, UserIdmStubEnforceDelUserStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_ENFORCE_DEL_USER;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubEnforceDelUserStub002, TestSize.Level0)
{
    int32_t testUserId = 83462;

    sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    EXPECT_NE(callback, nullptr);
    MockUserIdmService service;
    EXPECT_CALL(service, EnforceDelUser(_, _)).Times(1);
    ON_CALL(service, EnforceDelUser)
        .WillByDefault(
            [&testUserId](int32_t userId, const sptr<IdmCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
                return SUCCESS;
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_ENFORCE_DEL_USER;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));

    int32_t result = FAIL;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserIdmStubTest, UserIdmStubDelUserStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_DEL_USER;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubDelUserStub002, TestSize.Level0)
{
    int32_t testUserId = 72342;
    std::vector<uint8_t> testAuthToken = {1, 3, 5, 7};

    sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    EXPECT_NE(callback, nullptr);
    MockUserIdmService service;
    EXPECT_CALL(service, DelUser(_, _, _)).Times(1);
    ON_CALL(service, DelUser)
        .WillByDefault(
            [&testUserId, &testAuthToken](int32_t userId, const std::vector<uint8_t> authToken,
                const sptr<IdmCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_THAT(authToken, ElementsAreArray(testAuthToken));
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_DEL_USER;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testAuthToken));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubDelCredentialStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_DEL_CRED;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    MockUserIdmService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubDelCredentialStub002, TestSize.Level0)
{
    int32_t testUserId = 93261;
    uint64_t testCredentialId = 72632;
    std::vector<uint8_t> testAuthToken = {3, 5, 7, 9};

    sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    EXPECT_NE(callback, nullptr);
    MockUserIdmService service;
    EXPECT_CALL(service, DelCredential(_, _, _, _)).Times(1);
    ON_CALL(service, DelCredential)
        .WillByDefault(
            [&testUserId, &testCredentialId, &testAuthToken](int32_t userId, uint64_t credentialId,
                const std::vector<uint8_t> &authToken, const sptr<IdmCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(credentialId, testCredentialId);
                EXPECT_THAT(authToken, ElementsAreArray(testAuthToken));
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserIdmInterface::USER_IDM_DEL_CRED;

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUint64(testCredentialId));
    EXPECT_TRUE(data.WriteUInt8Vector(testAuthToken));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS