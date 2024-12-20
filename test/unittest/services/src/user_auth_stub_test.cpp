/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "user_auth_stub_test.h"

#include "iam_common_defines.h"
#include "mock_auth_event_listener.h"
#include "mock_user_auth_callback.h"
#include "mock_user_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthStubTest::SetUpTestCase()
{
}

void UserAuthStubTest::TearDownTestCase()
{
}

void UserAuthStubTest::SetUp()
{
}

void UserAuthStubTest::TearDown()
{
}

HWTEST_F(UserAuthStubTest, UserAuthStubDefault, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_ON_SEND_COMMAND;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(305, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetEnrolledStateStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_GET_ENROLLED_STATE;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetEnrolledStateStub002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MockUserAuthService service;
    int32_t testApiVersion = 12;
    AuthType testAuthType = FACE;
    uint64_t expectCredentialDigest = 23962;
    uint16_t expectCredentialCount = 1;
    EXPECT_CALL(service, GetEnrolledState(_, _, _)).Times(1);
    ON_CALL(service, GetEnrolledState)
        .WillByDefault(
            [testApiVersion, testAuthType, expectCredentialDigest, expectCredentialCount](int32_t apiVersion,
                AuthType authType, EnrolledState &enrolledState) {
                EXPECT_EQ(apiVersion, testApiVersion);
                EXPECT_EQ(authType, testAuthType);
                enrolledState.credentialDigest = expectCredentialDigest;
                enrolledState.credentialCount = expectCredentialCount;
                return SUCCESS;
            }
        );

    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(UserAuthInterfaceCode::USER_AUTH_GET_ENROLLED_STATE);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testApiVersion));
    EXPECT_TRUE(data.WriteUint32(testAuthType));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result = FAIL;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(SUCCESS, result);
    uint64_t actualCredentialDigest;
    EXPECT_TRUE(reply.ReadUint64(actualCredentialDigest));
    EXPECT_EQ(expectCredentialDigest, actualCredentialDigest);
    uint16_t actualCredentialCount;
    EXPECT_TRUE(reply.ReadUint16(actualCredentialCount));
    EXPECT_EQ(expectCredentialCount, actualCredentialCount);
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetAvailableStatusStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_GET_AVAILABLE_STATUS;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetAvailableStatusStub002, TestSize.Level0)
{
    MockUserAuthService service;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL3;
    int32_t testApiVersion = 8;
    int32_t testUserId = 100;
    EXPECT_CALL(service, GetAvailableStatus(_, _, _, _)).WillRepeatedly([]() {
        return SUCCESS;
    });

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = static_cast<uint32_t>(UserAuthInterfaceCode::USER_AUTH_GET_AVAILABLE_STATUS);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteUint32(testAuthTrustLevel));
    EXPECT_TRUE(data.WriteInt32(testApiVersion));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result = FAIL;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetPropertyStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_GET_PROPERTY;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetPropertyStub002, TestSize.Level0)
{
    int32_t testUserId = 1232666;
    AuthType testAuthType = FACE;
    std::vector<Attributes::AttributeKey> testAttrKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_SCHEDULE_MODE};
    std::vector<uint32_t> tempKeys;
    for (auto &attrKey : testAttrKeys) {
        tempKeys.push_back(static_cast<uint32_t>(attrKey));
    }
    sptr<MockGetExecutorPropertyCallback> callback(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    EXPECT_CALL(service, GetProperty(_, _, _, _)).Times(1);
    ON_CALL(service, GetProperty)
        .WillByDefault(
            [&testUserId, &testAuthType, &testAttrKeys](int32_t userId, AuthType authType,
                const std::vector<Attributes::AttributeKey> &keys,
                sptr<GetExecutorPropertyCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testAuthType);
                EXPECT_THAT(keys, ElementsAreArray(testAttrKeys));
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnGetExecutorPropertyResult(SUCCESS, attr);
                }
            }
        );
    EXPECT_CALL(*callback, OnGetExecutorPropertyResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_GET_PROPERTY;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteUInt32Vector(tempKeys));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubSetPropertyStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_SET_PROPERTY;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubSetPropertyStub002, TestSize.Level0)
{
    int32_t testUserId = 132282;
    AuthType testAuthType = FACE;
    Attributes attributes;

    uint64_t testTemplateId = 3364734;
    EXPECT_TRUE(attributes.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, testTemplateId));

    sptr<MockSetExecutorPropertyCallback> callback(new (std::nothrow) MockSetExecutorPropertyCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    EXPECT_CALL(service, SetProperty(_, _, _, _)).Times(1);
    ON_CALL(service, SetProperty)
        .WillByDefault(
            [&testUserId, &testAuthType, &testTemplateId](int32_t userId, AuthType authType,
                const Attributes &attributes, sptr<SetExecutorPropertyCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testAuthType);
                uint64_t tempTemplateId = 0;
                EXPECT_TRUE(attributes.GetUint64Value(Attributes::ATTR_TEMPLATE_ID, tempTemplateId));
                EXPECT_EQ(tempTemplateId, testTemplateId);
                if (callback != nullptr) {
                    callback->OnSetExecutorPropertyResult(SUCCESS);
                }
            }
        );
    EXPECT_CALL(*callback, OnSetExecutorPropertyResult(_)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_SET_PROPERTY;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteUInt8Vector(attributes.Serialize()));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthStub002, TestSize.Level0)
{
    int32_t testUserId = 3467;
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 4, 5};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    uint64_t testContextId = 2346782;

    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    EXPECT_CALL(service, Auth(_, _, _, _, _)).Times(1);
    ON_CALL(service, Auth)
        .WillByDefault(
            [&testChallenge, &testAuthType, &testAtl, &testContextId, &testApiVersion](int32_t apiVersion,
                const std::vector<uint8_t> &challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_EQ(apiVersion, testApiVersion);
                EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
                EXPECT_EQ(authType, testAuthType);
                EXPECT_EQ(authTrustLevel, testAtl);
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
                return testContextId;
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testApiVersion));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    uint64_t contextId = 0;
    EXPECT_TRUE(reply.ReadUint64(contextId));
    EXPECT_EQ(contextId, testContextId);
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub002, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    uint64_t testContextId = 2346728;

    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    EXPECT_CALL(service, AuthUser(_, _, _)).Times(1);
    ON_CALL(service, AuthUser)
        .WillByDefault(
            [&testUserId, &testChallenge, &testAuthType, &testAtl, &testContextId](AuthParamInner &authParam,
            std::optional<RemoteAuthParam> &remoteAuthParam, sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_EQ(authParam.userId, testUserId);
                EXPECT_THAT(authParam.challenge, ElementsAreArray(testChallenge));
                EXPECT_EQ(authParam.authType, testAuthType);
                EXPECT_EQ(authParam.authTrustLevel, testAtl);
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
                return testContextId;
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    uint32_t testAuthTrustLevel = 0;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(testAuthTrustLevel));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    uint64_t contextId = 0;
    EXPECT_TRUE(reply.ReadUint64(contextId));
    EXPECT_EQ(contextId, testContextId);
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub003, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub004, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    uint64_t testContextId = 2346728;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    EXPECT_CALL(service, AuthUser(_, _, _)).Times(1);
    ON_CALL(service, AuthUser)
        .WillByDefault(
            [&testUserId, &testChallenge, &testAuthType, &testAtl, &testContextId](AuthParamInner &authParam,
            std::optional<RemoteAuthParam> &remoteAuthParam, sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_THAT(authParam.challenge, ElementsAreArray(testChallenge));
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
                return testContextId;
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    uint32_t collectorTokenId = 123;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("verifierNetworkId"));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("collectorNetworkId"));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteUint32(collectorTokenId));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub005, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    uint32_t collectorTokenId = 123;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("verifierNetworkId"));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("collectorNetworkId"));
    EXPECT_TRUE(data.WriteBool(false));
    EXPECT_TRUE(data.WriteUint32(collectorTokenId));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub006, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("verifierNetworkId"));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("collectorNetworkId"));
    EXPECT_TRUE(data.WriteBool(false));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub007, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("verifierNetworkId"));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("collectorNetworkId"));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub008, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("verifierNetworkId"));
    EXPECT_TRUE(data.WriteBool(false));
    EXPECT_TRUE(data.WriteString("collectorNetworkId"));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub009, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("verifierNetworkId"));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub010, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub011, TestSize.Level0)
{
    int32_t testUserId = 3467;
    std::vector<uint8_t> testChallenge = {1, 2, 5, 9};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    sptr<MockAuthEventListenerService> callback(new (std::nothrow) MockAuthEventListenerService());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_AUTH_USER;
    std::vector<int32_t> testAuthTypeInts;
    testAuthTypeInts.push_back(static_cast<AuthType>(1));
    uint32_t authIntent = 0;
    uint32_t collectorTokenId = 123;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteInt32Vector(testAuthTypeInts));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_TRUE(data.WriteUint32(authIntent));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("verifierNetworkId"));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteString("collectorNetworkId"));
    EXPECT_TRUE(data.WriteBool(true));
    EXPECT_TRUE(data.WriteUint32(collectorTokenId));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(GENERAL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubIdentifyStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_IDENTIFY;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubIdentifyStub002, TestSize.Level0)
{
    std::vector<uint8_t> testChallenge = {1, 2, 5, 8, 9};
    AuthType testAuthType = FACE;
    uint64_t testContextId = 76374284;

    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    EXPECT_CALL(service, Identify(_, _, _)).Times(1);
    ON_CALL(service, Identify)
        .WillByDefault(
            [&testChallenge, &testAuthType, &testContextId](const std::vector<uint8_t> &challenge, AuthType authType,
                sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
                EXPECT_EQ(authType, testAuthType);
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnResult(SUCCESS, attr);
                }
                return testContextId;
            }
        );
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_IDENTIFY;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    uint64_t contextId = 0;
    EXPECT_TRUE(reply.ReadUint64(contextId));
    EXPECT_EQ(contextId, testContextId);
}

HWTEST_F(UserAuthStubTest, UserAuthStubCancelAuthOrIdentifyStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_CANCEL_AUTH;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubCancelAuthOrIdentifyStub002, TestSize.Level0)
{
    uint64_t testContextId = 9346248;

    MockUserAuthService service;
    EXPECT_CALL(service, CancelAuthOrIdentify(_)).Times(1);
    ON_CALL(service, CancelAuthOrIdentify)
        .WillByDefault(
            [&testContextId](uint64_t contextId) {
                EXPECT_EQ(contextId, testContextId);
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_CANCEL_AUTH;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(testContextId));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result = FAIL;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserAuthStubTest, UserAuthStubCancelAuthOrIdentifyStub003, TestSize.Level0)
{
    uint64_t testContextId = 9346248;

    MockUserAuthService service;
    EXPECT_CALL(service, CancelAuthOrIdentify(_)).Times(1);
    ON_CALL(service, CancelAuthOrIdentify)
        .WillByDefault(
            [&testContextId](uint64_t contextId) {
                EXPECT_EQ(contextId, testContextId);
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_CANCEL_IDENTIFY;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(testContextId));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result = FAIL;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetVersionStub, TestSize.Level0)
{
    int32_t testVersion = 1000;

    MockUserAuthService service;
    EXPECT_CALL(service, GetVersion(_)).Times(1);
    ON_CALL(service, GetVersion)
        .WillByDefault(
            [&testVersion](int32_t &version) {
                version = testVersion;
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_GET_VERSION;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t version = -1;
    EXPECT_TRUE(reply.ReadInt32(version));
    EXPECT_EQ(version, testVersion);
    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserAuthStubTest, UserAuthStubRegistUserAuthSuccessEventListenerStub, TestSize.Level0)
{
    MockUserAuthService service;
    sptr<MockAuthEventListenerService> callback(new (std::nothrow) MockAuthEventListenerService());
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(service, RegistUserAuthSuccessEventListener(_, _)).Times(1);
    ON_CALL(service, RegistUserAuthSuccessEventListener)
        .WillByDefault(
            [](const std::vector<AuthType> &authType, const sptr<AuthEventListenerInterface> &callback) {
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_REG_EVENT_LISTENER;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    std::vector<int32_t> authType;
    authType.push_back(static_cast<int32_t>(PIN));
    authType.push_back(static_cast<int32_t>(FACE));
    authType.push_back(static_cast<int32_t>(FINGERPRINT));

    EXPECT_TRUE(data.WriteInt32Vector(authType));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserAuthStubTest, UserAuthStubUnRegistUserAuthSuccessEventListenerStub, TestSize.Level0)
{
    MockUserAuthService service;
    sptr<MockAuthEventListenerService> callback(new (std::nothrow) MockAuthEventListenerService());
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(service, UnRegistUserAuthSuccessEventListener(_)).Times(1);
    ON_CALL(service, UnRegistUserAuthSuccessEventListener)
        .WillByDefault(
            [](const sptr<AuthEventListenerInterface> &callback) {
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_UNREG_EVENT_LISTENER;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserAuthStubTest, UserAuthStubSetGlobalConfigParamStub001, TestSize.Level0)
{
    MockUserAuthService service;
    EXPECT_CALL(service, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(service, SetGlobalConfigParam)
        .WillByDefault(
            [](const GlobalConfigParam &param) {
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_SET_CLOBAL_CONFIG_PARAM;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    GlobalConfigParam param = {};
    param.type = PIN_EXPIRED_PERIOD;
    param.value.pinExpiredPeriod = 1;
    EXPECT_TRUE(data.WriteInt32(param.type));
    EXPECT_TRUE(data.WriteInt64(param.value.pinExpiredPeriod));
    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserAuthStubTest, UserAuthStubSetGlobalConfigParamStub002, TestSize.Level0)
{
    MockUserAuthService service;
    EXPECT_CALL(service, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(service, SetGlobalConfigParam)
        .WillByDefault(
            [](const GlobalConfigParam &param) {
                return GENERAL_ERROR;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_SET_CLOBAL_CONFIG_PARAM;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    GlobalConfigParam param = {};
    param.type = ENABLE_STATUS;
    param.value.enableStatus = true;
    param.userIds.push_back(1);
    std::vector<int32_t> authTypes = {1};
    EXPECT_TRUE(data.WriteInt32(param.type));
    EXPECT_TRUE(data.WriteInt64(param.value.pinExpiredPeriod));
    EXPECT_TRUE(data.WriteInt32Vector(param.userIds));
    EXPECT_TRUE(data.WriteInt32Vector(authTypes));
    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, GENERAL_ERROR);
}

HWTEST_F(UserAuthStubTest, UserAuthStubPrepareRemoteAuthStub_001, TestSize.Level0)
{
    MockUserAuthService service;
    sptr<MockAuthEventListenerService> callback(new (std::nothrow) MockAuthEventListenerService());
    EXPECT_NE(callback, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_PREPARE_REMOTE_AUTH;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
    int32_t result;
    EXPECT_FALSE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(UserAuthStubTest, UserAuthStubPrepareRemoteAuthStub_002, TestSize.Level0)
{
    MockUserAuthService service;
    sptr<MockAuthEventListenerService> callback(new (std::nothrow) MockAuthEventListenerService());
    EXPECT_NE(callback, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_PREPARE_REMOTE_AUTH;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteString("collectorNetworkId"));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(GENERAL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubPrepareRemoteAuthStub_003, TestSize.Level0)
{
    MockUserAuthService service;
    sptr<MockUserAuthCallback> callback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(callback, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_PREPARE_REMOTE_AUTH;
    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteString("collectorNetworkId"));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS