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

#include "mock_user_auth_callback.h"
#include "mock_user_auth_service.h"
#include "result_code.h"

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

HWTEST_F(UserAuthStubTest, UserAuthStubGetAvailableStatusStub, TestSize.Level1)
{
    MockUserAuthService service;
    AuthType authType = FACE;
    AuthTrustLevel authTrustLevel = ATL3;
    EXPECT_CALL(service, GetAvailableStatus(FACE, ATL3)).WillOnce(Return(0));

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authType)));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authTrustLevel)));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_GET_AVAILABLE_STATUS, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetAvailableStatusStubFailed, TestSize.Level1)
{
    MockUserAuthService service;
    AuthType authType = FACE;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authType)));

    EXPECT_EQ(READ_PARCEL_ERROR,
        service.OnRemoteRequest(UserAuth::USER_AUTH_GET_AVAILABLE_STATUS, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetPropertyStub, TestSize.Level1)
{
    MockUserAuthService service;
    std::optional<int32_t> userId;
    AuthType authType = FACE;
    std::vector<Attributes::AttributeKey> attrKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_SCHEDULE_MODE};
    std::vector<uint32_t> keys;
    for (auto &attrKey : attrKeys) {
        keys.push_back(static_cast<uint32_t>(attrKey));
    }
    sptr<MockGetExecutorPropertyCallback> callback = new MockGetExecutorPropertyCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(service, GetProperty(userId, FACE, _, _)).Times(1);
    ON_CALL(service, GetProperty)
        .WillByDefault(
            [](std::optional<int32_t> userId, AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
                sptr<GetExecutorPropertyCallback> &callback) {
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnGetExecutorPropertyResult(SUCCESS, attr);
                }
            });
    EXPECT_CALL(*callback, OnGetExecutorPropertyResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authType)));
    EXPECT_TRUE(data.WriteUInt32Vector(keys));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_GET_PROPERTY, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetPropertyByIdStub, TestSize.Level1)
{
    MockUserAuthService service;
    std::optional<int32_t> userId = 1;
    AuthType authType = FACE;
    std::vector<Attributes::AttributeKey> attrKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_SCHEDULE_MODE};
    std::vector<uint32_t> keys;
    for (auto &attrKey : attrKeys) {
        keys.push_back(static_cast<uint32_t>(attrKey));
    }
    sptr<MockGetExecutorPropertyCallback> callback = new MockGetExecutorPropertyCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(service, GetProperty(userId, FACE, _, _)).Times(1);
    ON_CALL(service, GetProperty)
        .WillByDefault(
            [](std::optional<int32_t> userId, AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
                sptr<GetExecutorPropertyCallback> &callback) {
                if (callback != nullptr) {
                    Attributes attr;
                    callback->OnGetExecutorPropertyResult(SUCCESS, attr);
                }
            });
    EXPECT_CALL(*callback, OnGetExecutorPropertyResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(userId.value()));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authType)));
    EXPECT_TRUE(data.WriteUInt32Vector(keys));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_GET_PROPERTY_BY_ID, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubSetPropertyStub, TestSize.Level1)
{
    MockUserAuthService service;
    std::optional<int32_t> userId;
    AuthType authType = FACE;
    Attributes attributes;

    sptr<MockSetExecutorPropertyCallback> callback = new MockSetExecutorPropertyCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(service, SetProperty(userId, FACE, _, _)).Times(1);
    ON_CALL(service, SetProperty)
        .WillByDefault([](std::optional<int32_t> userId, AuthType authType, const Attributes &attributes,
                           sptr<SetExecutorPropertyCallback> &callback) {
            if (callback != nullptr) {
                callback->OnSetExecutorPropertyResult(SUCCESS);
            }
        });
    EXPECT_CALL(*callback, OnSetExecutorPropertyResult(_)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authType)));
    EXPECT_TRUE(data.WriteUInt8Vector(attributes.Serialize()));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_SET_PROPERTY, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthStub, TestSize.Level1)
{
    MockUserAuthService service;
    std::optional<int32_t> userId;
    uint64_t challenge = 124;
    AuthType authType = FACE;
    AuthTrustLevel atl = ATL2;

    sptr<MockUserAuthCallback> callback = new MockUserAuthCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(service, AuthUser(userId, _, FACE, atl, _)).Times(1);
    ON_CALL(service, AuthUser)
        .WillByDefault([](std::optional<int32_t> userId, const std::vector<uint8_t> &challenge, AuthType authType,
                           AuthTrustLevel authTrustLevel, sptr<UserAuthCallback> &callback) {
            if (callback != nullptr) {
                Attributes attr;
                callback->OnAuthResult(SUCCESS, attr);
            }
            uint64_t contextId = 300;
            return contextId;
        });
    EXPECT_CALL(*callback, OnAuthResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(challenge));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authType)));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(atl)));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_AUTH, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubAuthUserStub, TestSize.Level1)
{
    MockUserAuthService service;
    std::optional<int32_t> userId = 1;
    uint64_t challenge = 125;
    AuthType authType = FACE;
    AuthTrustLevel atl = ATL2;

    sptr<MockUserAuthCallback> callback = new MockUserAuthCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(service, AuthUser(userId, _, FACE, atl, _)).Times(1);
    ON_CALL(service, AuthUser)
        .WillByDefault([](std::optional<int32_t> userId, const std::vector<uint8_t> &challenge, AuthType authType,
                           AuthTrustLevel authTrustLevel, sptr<UserAuthCallback> &callback) {
            if (callback != nullptr) {
                Attributes attr;
                callback->OnAuthResult(SUCCESS, attr);
            }
            uint64_t contextId = 300;
            return contextId;
        });
    EXPECT_CALL(*callback, OnAuthResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(userId.value()));
    EXPECT_TRUE(data.WriteUint64(challenge));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authType)));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(atl)));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_AUTH_USER, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubIdentifyStub, TestSize.Level1)
{
    MockUserAuthService service;
    uint64_t challenge = 125;
    AuthType authType = FACE;

    sptr<MockUserAuthCallback> callback = new MockUserAuthCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(service, Identify(_, FACE, _)).Times(1);
    ON_CALL(service, Identify)
        .WillByDefault([](const std::vector<uint8_t> &challenge, AuthType authType, sptr<UserAuthCallback> &callback) {
            if (callback != nullptr) {
                Attributes attr;
                callback->OnIdentifyResult(SUCCESS, attr);
            }
            uint64_t contextId = 300;
            return contextId;
        });
    EXPECT_CALL(*callback, OnIdentifyResult(_, _)).Times(1);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(challenge));
    EXPECT_TRUE(data.WriteUint32(static_cast<uint32_t>(authType)));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_IDENTIFY, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubCancelAuthOrIdentifyStub, TestSize.Level1)
{
    MockUserAuthService service;
    const uint64_t CONTEXT_ID = 100;
    EXPECT_CALL(service, CancelAuthOrIdentify(100)).WillOnce(Return(0));

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));
    EXPECT_TRUE(data.WriteUint64(CONTEXT_ID));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_CANCEL_AUTH, data, reply, option));
}

HWTEST_F(UserAuthStubTest, UserAuthStubGetVersionStub, TestSize.Level1)
{
    MockUserAuthService service;
    EXPECT_CALL(service, GetVersion()).WillOnce(Return(0));

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_TRUE(data.WriteInterfaceToken(UserAuth::GetDescriptor()));

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(UserAuth::USER_AUTH_GET_VERSION, data, reply, option));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS