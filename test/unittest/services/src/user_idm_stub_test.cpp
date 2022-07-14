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
#include "result_code.h"
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

namespace {
constexpr int32_t IDM_STUB_TEST_USER_ID = 1;
const vector<uint8_t> IDM_STUB_TEST_AUTH_TOKEN = {1, 2, 3, 4, 5};
constexpr uint64_t IDM_STUB_TEST_CHALLENGE = 0x1234567890;
constexpr uint64_t IDM_STUB_TEST_CRED_ID = 1;
vector<uint8_t> g_challengeVectorTest;
} // namespace

void UserIdmStubTest::SetUpTestCase()
{
}

void UserIdmStubTest::TearDownTestCase()
{
}

void UserIdmStubTest::SetUp()
{
    g_challengeVectorTest.resize(sizeof(IDM_STUB_TEST_CHALLENGE));
    (void)memcpy_s(g_challengeVectorTest.data(), g_challengeVectorTest.size(), &IDM_STUB_TEST_CHALLENGE,
        sizeof(IDM_STUB_TEST_CHALLENGE));
}

void UserIdmStubTest::TearDown()
{
}

HWTEST_F(UserIdmStubTest, UserIdmStubOpenSessionStub, TestSize.Level0)
{
    MockUserIdmService service;
    EXPECT_CALL(service, OpenSession(Eq(std::nullopt), _)).Times(1);
    ON_CALL(service, OpenSession).WillByDefault([](std::optional<int32_t> userId, std::vector<uint8_t> &challenge) {
        challenge = g_challengeVectorTest;
        return SUCCESS;
    });

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_OPEN_SESSION, data, reply, option));

    uint64_t challenge;
    EXPECT_TRUE(reply.ReadUint64(challenge));
    EXPECT_EQ(challenge, IDM_STUB_TEST_CHALLENGE);
}

HWTEST_F(UserIdmStubTest, UserIdmStubOpenSessionByIdStub, TestSize.Level0)
{
    MockUserIdmService service;
    EXPECT_CALL(service, OpenSession(Eq(IDM_STUB_TEST_USER_ID), _)).Times(1);
    ON_CALL(service, OpenSession).WillByDefault([](std::optional<int32_t> userId, std::vector<uint8_t> &challenge) {
        challenge = g_challengeVectorTest;
        return SUCCESS;
    });

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_OPEN_SESSION_BY_ID, data, reply, option));

    uint64_t challenge;
    EXPECT_TRUE(reply.ReadUint64(challenge));
    EXPECT_EQ(challenge, IDM_STUB_TEST_CHALLENGE);
}

HWTEST_F(UserIdmStubTest, UserIdmStubCloseSessionStub, TestSize.Level0)
{
    MockUserIdmService service;
    EXPECT_CALL(service, CloseSession(Eq(std::nullopt))).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_CLOSE_SESSION, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubCloseSessionByIdStub, TestSize.Level0)
{
    MockUserIdmService service;
    EXPECT_CALL(service, CloseSession(Eq(IDM_STUB_TEST_USER_ID))).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_CLOSE_SESSION_BY_ID, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubGetCredentialInfoStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmGetCredentialInfoCallback> callback = new (std::nothrow) MockIdmGetCredentialInfoCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, GetCredentialInfo(Eq(std::nullopt), FACE, _)).Times(1);
    ON_CALL(service, GetCredentialInfo)
        .WillByDefault([](std::optional<int32_t> userId, AuthType authType,
                           const sptr<IdmGetCredInfoCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                std::vector<std::shared_ptr<CredentialInfo>> infoList;
                callback->OnCredentialInfos(infoList, std::nullopt);
            }
            return SUCCESS;
        });
    EXPECT_CALL(*callback, OnCredentialInfos(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(FACE));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_GET_AUTH_INFO, data, reply, option));

    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
}

HWTEST_F(UserIdmStubTest, UserIdmStubGetCredentialInfoByIdStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmGetCredentialInfoCallback> callback = new (std::nothrow) MockIdmGetCredentialInfoCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, GetCredentialInfo(Eq(IDM_STUB_TEST_USER_ID), FACE, _)).Times(1);
    ON_CALL(service, GetCredentialInfo)
        .WillByDefault([](std::optional<int32_t> userId, AuthType authType,
                           const sptr<IdmGetCredInfoCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                std::vector<std::shared_ptr<CredentialInfo>> infoList;
                callback->OnCredentialInfos(infoList, std::nullopt);
            }
            return SUCCESS;
        });
    EXPECT_CALL(*callback, OnCredentialInfos(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));
    EXPECT_TRUE(data.WriteUint32(FACE));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_GET_AUTH_INFO_BY_ID, data, reply, option));

    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
}

HWTEST_F(UserIdmStubTest, UserIdmStubGetSecInfoStub, TestSize.Level0)
{
    MockUserIdmService service;
    sptr<MockIdmGetSecureUserInfoCallback> callback = new (std::nothrow) MockIdmGetSecureUserInfoCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, GetSecInfo(Eq(IDM_STUB_TEST_USER_ID), _)).Times(1);
    ON_CALL(service, GetSecInfo)
        .WillByDefault([](std::optional<int32_t> userId, const sptr<IdmGetSecureUserInfoCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                const std::shared_ptr<SecureUserInfo> info;
                callback->OnSecureUserInfo(info);
            }
            return SUCCESS;
        });
    EXPECT_CALL(*callback, OnSecureUserInfo(_)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_GET_SEC_INFO, data, reply, option));

    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
}

HWTEST_F(UserIdmStubTest, UserIdmStubAddCredentialStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, AddCredential(Eq(std::nullopt), PIN, PIN_SIX, IsEmpty(), _, false)).Times(1);
    ON_CALL(service, AddCredential)
        .WillByDefault(
            [](std::optional<int32_t> userId, AuthType authType, PinSubType pinSubType,
                const std::vector<uint8_t> &token, const sptr<IdmCallbackInterface> &callback, bool isUpdate) {
                EXPECT_NE(callback, nullptr);
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
            });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(PIN));
    EXPECT_TRUE(data.WriteUint64(PIN_SIX));
    EXPECT_TRUE(data.WriteUInt8Vector(IDM_STUB_TEST_AUTH_TOKEN));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_ADD_CREDENTIAL, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubAddCredentialByIdStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, AddCredential(Eq(IDM_STUB_TEST_USER_ID), PIN, PIN_SIX, IsEmpty(), _, false)).Times(1);
    ON_CALL(service, AddCredential)
        .WillByDefault(
            [](std::optional<int32_t> userId, AuthType authType, PinSubType pinSubType,
                const std::vector<uint8_t> &token, const sptr<IdmCallbackInterface> &callback, bool isUpdate) {
                EXPECT_NE(callback, nullptr);
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
            });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));
    EXPECT_TRUE(data.WriteUint32(PIN));
    EXPECT_TRUE(data.WriteUint64(PIN_SIX));
    EXPECT_TRUE(data.WriteUInt8Vector(IDM_STUB_TEST_AUTH_TOKEN));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_ADD_CREDENTIAL_BY_ID, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubUpdateCredentialStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, UpdateCredential(Eq(std::nullopt), PIN, PIN_SIX, Eq(IDM_STUB_TEST_AUTH_TOKEN), _)).Times(1);
    ON_CALL(service, UpdateCredential)
        .WillByDefault([](std::optional<int32_t> userId, AuthType authType, PinSubType pinSubType,
                           const std::vector<uint8_t> &token, const sptr<IdmCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                Attributes attr;
                callback->OnResult(SUCCESS, attr);
            }
        });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(PIN));
    EXPECT_TRUE(data.WriteUint64(PIN_SIX));
    EXPECT_TRUE(data.WriteUInt8Vector(IDM_STUB_TEST_AUTH_TOKEN));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_UPDATE_CREDENTIAL, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubUpdateCredentialByIdStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, UpdateCredential(Eq(IDM_STUB_TEST_USER_ID), PIN, PIN_SIX, Eq(IDM_STUB_TEST_AUTH_TOKEN), _))
        .Times(1);
    ON_CALL(service, UpdateCredential)
        .WillByDefault([](std::optional<int32_t> userId, AuthType authType, PinSubType pinSubType,
                           const std::vector<uint8_t> &token, const sptr<IdmCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                Attributes attr;
                callback->OnResult(SUCCESS, attr);
            }
        });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));
    EXPECT_TRUE(data.WriteUint32(PIN));
    EXPECT_TRUE(data.WriteUint64(PIN_SIX));
    EXPECT_TRUE(data.WriteUInt8Vector(IDM_STUB_TEST_AUTH_TOKEN));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS,
        service.OnRemoteRequest(UserIdmInterface::USER_IDM_UPDATE_CREDENTIAL_BY_ID, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubCancelStub, TestSize.Level0)
{
    MockUserIdmService service;
    EXPECT_CALL(service, Cancel(Eq(std::nullopt), Eq(g_challengeVectorTest))).WillOnce(Return(SUCCESS));

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(IDM_STUB_TEST_CHALLENGE));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_CANCEL, data, reply, option));

    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
}

HWTEST_F(UserIdmStubTest, UserIdmStubCancelByIdStub, TestSize.Level0)
{
    MockUserIdmService service;
    EXPECT_CALL(service, Cancel(Eq(IDM_STUB_TEST_USER_ID), Eq(std::nullopt))).WillOnce(Return(SUCCESS));

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_CANCEL_BY_ID, data, reply, option));

    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
}

HWTEST_F(UserIdmStubTest, UserIdmStubEnforceDelUserStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, EnforceDelUser(Eq(IDM_STUB_TEST_USER_ID), _)).Times(1);
    ON_CALL(service, EnforceDelUser).WillByDefault([](int32_t userId, const sptr<IdmCallbackInterface> &callback) {
        EXPECT_NE(callback, nullptr);
        if (callback != nullptr) {
            Attributes attr;
            callback->OnResult(SUCCESS, attr);
        }
        return SUCCESS;
    });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_ENFORCE_DEL_USER, data, reply, option));

    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
}

HWTEST_F(UserIdmStubTest, UserIdmStubDelUserStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, DelUser(Eq(std::nullopt), Eq(IDM_STUB_TEST_AUTH_TOKEN), _)).Times(1);
    ON_CALL(service, DelUser)
        .WillByDefault([](std::optional<int32_t> userId, const std::vector<uint8_t> authToken,
                           const sptr<IdmCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                Attributes attr;
                callback->OnResult(SUCCESS, attr);
            }
            return SUCCESS;
        });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUInt8Vector(IDM_STUB_TEST_AUTH_TOKEN));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_DEL_USER, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubDelUserByIdStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, DelUser(Eq(IDM_STUB_TEST_USER_ID), Eq(IDM_STUB_TEST_AUTH_TOKEN), _)).Times(1);
    ON_CALL(service, DelUser)
        .WillByDefault([](std::optional<int32_t> userId, const std::vector<uint8_t> authToken,
                           const sptr<IdmCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                Attributes attr;
                callback->OnResult(SUCCESS, attr);
            }
            return SUCCESS;
        });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));
    EXPECT_TRUE(data.WriteUInt8Vector(IDM_STUB_TEST_AUTH_TOKEN));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_DEL_USER_BY_ID, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubDelCredentialStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service, DelCredential(Eq(std::nullopt), Eq(IDM_STUB_TEST_CRED_ID), Eq(IDM_STUB_TEST_AUTH_TOKEN), _))
        .Times(1);
    ON_CALL(service, DelCredential)
        .WillByDefault([](std::optional<int32_t> userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
                           const sptr<IdmCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                Attributes attr;
                callback->OnResult(SUCCESS, attr);
            }
        });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(IDM_STUB_TEST_CRED_ID));
    EXPECT_TRUE(data.WriteUInt8Vector(IDM_STUB_TEST_AUTH_TOKEN));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_DEL_CRED, data, reply, option));
}

HWTEST_F(UserIdmStubTest, UserIdmStubDelCredentialByIdStub, TestSize.Level0)
{
    MockUserIdmService service;
    const sptr<MockIdmCallback> callback = new (std::nothrow) MockIdmCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(service,
        DelCredential(Eq(IDM_STUB_TEST_USER_ID), Eq(IDM_STUB_TEST_CRED_ID), Eq(IDM_STUB_TEST_AUTH_TOKEN), _))
        .Times(1);
    ON_CALL(service, DelCredential)
        .WillByDefault([](std::optional<int32_t> userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
                           const sptr<IdmCallbackInterface> &callback) {
            EXPECT_NE(callback, nullptr);
            if (callback != nullptr) {
                Attributes attr;
                callback->OnResult(SUCCESS, attr);
            }
        });
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserIdmInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(IDM_STUB_TEST_USER_ID));
    EXPECT_TRUE(data.WriteUint64(IDM_STUB_TEST_CRED_ID));
    EXPECT_TRUE(data.WriteUInt8Vector(IDM_STUB_TEST_AUTH_TOKEN));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserIdmInterface::USER_IDM_DEL_CREDENTIAL, data, reply, option));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS