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

#include "user_auth_proxy_test.h"

#include "iam_ptr.h"
#include "user_auth_proxy.h"
#include "mock_remote_object.h"
#include "mock_user_auth_service.h"
#include "mock_user_auth_client_callback.h"
#include "user_auth_callback_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthProxyTest::SetUpTestCase()
{
}

void UserAuthProxyTest::TearDownTestCase()
{
}

void UserAuthProxyTest::SetUp()
{
}

void UserAuthProxyTest::TearDown()
{
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetAvailableStatus, TestSize.Level0)
{
    static const int32_t testApiVersion = 0;
    static const AuthType testAuthType = FACE;
    static const AuthTrustLevel testAuthTrustLevel = ATL3;
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetAvailableStatus(_, _, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel) {
            EXPECT_EQ(testApiVersion, apiVersion);
            EXPECT_EQ(testAuthType, authType);
            EXPECT_EQ(testAuthTrustLevel, authTrustLevel);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetProperty, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const AuthType testAuthType = FACE;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_SCHEDULE_MODE};

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback =
        new (std::nothrow) GetExecutorPropertyCallbackService(getPropCallback);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetProperty(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](std::optional<int32_t> userId, AuthType authType,
            const std::vector<Attributes::AttributeKey> &keys, sptr<GetExecutorPropertyCallbackInterface> &callback) {
            EXPECT_TRUE(userId.has_value());
            EXPECT_EQ(userId.value(), testUserId);
            EXPECT_EQ(authType, testAuthType);
            EXPECT_THAT(keys, ElementsAre(Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
                Attributes::ATTR_SCHEDULE_MODE));
            EXPECT_EQ(callback, testCallback);
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->GetProperty(testUserId, testAuthType, testKeys, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxySetProperty, TestSize.Level0)
{
    static const AuthType testAuthType = FACE;

    Attributes testAttr;
    EXPECT_EQ(testAttr.SetInt32Value(Attributes::ATTR_RESULT_CODE, 1), true);

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto setPropCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(setPropCallback, nullptr);
    sptr<SetExecutorPropertyCallbackInterface> testCallback =
        new (std::nothrow) SetExecutorPropertyCallbackService(setPropCallback);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetProperty(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t userId, AuthType authType,
            const Attributes &attributes, sptr<SetExecutorPropertyCallbackInterface> &callback) {
            EXPECT_EQ(userId, 0);
            EXPECT_EQ(authType, testAuthType);
            int32_t resultCode;
            EXPECT_EQ(attributes.GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode), true);
            EXPECT_EQ(resultCode, 1);
            EXPECT_EQ(callback, testCallback);
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->SetProperty(0, testAuthType, testAttr, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuth, TestSize.Level0)
{
    static const int32_t testApiVersion = 0;
    static const AuthType testAuthType = FACE;
    static const AuthTrustLevel testAtl = ATL1;
    const std::vector<uint8_t> testChallenge = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback =
        new (std::nothrow) UserAuthCallbackService(authCallback);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Auth(_, _, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t apiVersion, const std::vector<uint8_t> &challenge,
            AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback) {
            EXPECT_EQ(apiVersion, testApiVersion);
            EXPECT_THAT(challenge, ElementsAre(1, 2, 3, 4));
            EXPECT_EQ(authType, testAuthType);
            EXPECT_EQ(authTrustLevel, testAtl);
            EXPECT_EQ(callback, testCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->Auth(testApiVersion, testChallenge, testAuthType, testAtl, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuthUser, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const AuthType testAuthType = FACE;
    static const AuthTrustLevel testAtl = ATL1;
    const std::vector<uint8_t> testChallenge = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback =
        new (std::nothrow) UserAuthCallbackService(authCallback);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AuthUser(_, _, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t userId, const std::vector<uint8_t> &challenge,
            AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback) {
            EXPECT_EQ(userId, testUserId);
            EXPECT_THAT(challenge, ElementsAre(1, 2, 3, 4));
            EXPECT_EQ(authType, testAuthType);
            EXPECT_EQ(authTrustLevel, testAtl);
            EXPECT_EQ(callback, testCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->AuthUser(testUserId, testChallenge, testAuthType, testAtl, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyCancelAuthOrIdentify, TestSize.Level0)
{
    static const uint64_t testContextId = 200;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelAuthOrIdentify(_))
        .Times(Exactly(1))
        .WillOnce([](uint64_t contextId) {
            EXPECT_EQ(contextId, testContextId);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->CancelAuthOrIdentify(testContextId);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyIdentify, TestSize.Level0)
{
    static const AuthType testAuthType = FACE;
    const std::vector<uint8_t> testChallenge = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto identifyCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(identifyCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback =
        new (std::nothrow) UserAuthCallbackService(identifyCallback);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Identify(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](const std::vector<uint8_t> &challenge, AuthType authType,
            sptr<UserAuthCallbackInterface> &callback) {
            EXPECT_THAT(challenge, ElementsAre(1, 2, 3, 4));
            EXPECT_EQ(authType, testAuthType);
            EXPECT_EQ(callback, testCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->Identify(testChallenge, testAuthType, testCallback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS