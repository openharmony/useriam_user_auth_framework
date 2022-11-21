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

#include "user_auth_stub_test.h"

#include "iam_common_defines.h"
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

HWTEST_F(UserAuthStubTest, UserAuthStubGetAvailableStatusStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterface::USER_AUTH_GET_AVAILABLE_STATUS;

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
    EXPECT_CALL(service, GetAvailableStatus(_, _, _)).Times(1);
    ON_CALL(service, GetAvailableStatus)
        .WillByDefault(
            [&testAuthType, &testAuthTrustLevel, &testApiVersion](int32_t apiVersion, AuthType authType,
                AuthTrustLevel authTrustLevel) {
                EXPECT_EQ(apiVersion, testApiVersion);
                EXPECT_EQ(authType, testAuthType);
                EXPECT_EQ(authTrustLevel, testAuthTrustLevel);
                return SUCCESS;
            }
        );

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterface::USER_AUTH_GET_AVAILABLE_STATUS;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
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
    uint32_t code = UserAuthInterface::USER_AUTH_GET_PROPERTY;

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
    sptr<MockGetExecutorPropertyCallback> callback = new MockGetExecutorPropertyCallback();
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
    uint32_t code = UserAuthInterface::USER_AUTH_GET_PROPERTY;

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
    uint32_t code = UserAuthInterface::USER_AUTH_SET_PROPERTY;

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

    sptr<MockSetExecutorPropertyCallback> callback = new MockSetExecutorPropertyCallback();
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
    uint32_t code = UserAuthInterface::USER_AUTH_SET_PROPERTY;

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
    uint32_t code = UserAuthInterface::USER_AUTH_AUTH;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthStub002, TestSize.Level0)
{
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 4, 5};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL2;
    uint64_t testContextId = 2346782;

    sptr<MockUserAuthCallback> callback = new MockUserAuthCallback();
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
    uint32_t code = UserAuthInterface::USER_AUTH_AUTH;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    EXPECT_TRUE(data.WriteInt32(testApiVersion));

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
    uint32_t code = UserAuthInterface::USER_AUTH_AUTH_USER;

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

    sptr<MockUserAuthCallback> callback = new MockUserAuthCallback();
    EXPECT_NE(callback, nullptr);
    MockUserAuthService service;
    EXPECT_CALL(service, AuthUser(_, _, _, _, _)).Times(1);
    ON_CALL(service, AuthUser)
        .WillByDefault(
            [&testUserId, &testChallenge, &testAuthType, &testAtl, &testContextId](int32_t userId,
                const std::vector<uint8_t> &challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
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
    uint32_t code = UserAuthInterface::USER_AUTH_AUTH_USER;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testUserId));
    EXPECT_TRUE(data.WriteUInt8Vector(testChallenge));
    EXPECT_TRUE(data.WriteInt32(testAuthType));
    EXPECT_TRUE(data.WriteUint32(testAtl));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    uint64_t contextId = 0;
    EXPECT_TRUE(reply.ReadUint64(contextId));
    EXPECT_EQ(contextId, testContextId);
}

HWTEST_F(UserAuthStubTest, UserAuthStubIdentifyStub001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterface::USER_AUTH_IDENTIFY;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    MockUserAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubIdentifyStub002, TestSize.Level0)
{
    std::vector<uint8_t> testChallenge = {1, 2, 5, 8, 9};
    AuthType testAuthType = FACE;
    uint64_t testContextId = 76374284;

    sptr<MockUserAuthCallback> callback = new MockUserAuthCallback();
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
    uint32_t code = UserAuthInterface::USER_AUTH_IDENTIFY;

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
    uint32_t code = UserAuthInterface::USER_AUTH_CANCEL_AUTH;

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
    uint32_t code = UserAuthInterface::USER_AUTH_CANCEL_AUTH;

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
    uint32_t code = UserAuthInterface::USER_AUTH_GET_VERSION;

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuthInterface::GetDescriptor()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    int32_t version = -1;
    EXPECT_TRUE(reply.ReadInt32(version));
    EXPECT_EQ(version, testVersion);
    int32_t result;
    EXPECT_TRUE(reply.ReadInt32(result));
    EXPECT_EQ(result, SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS