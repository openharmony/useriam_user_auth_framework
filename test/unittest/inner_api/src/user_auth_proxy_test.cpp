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

#include "user_auth_proxy_test.h"

#include "iam_ptr.h"
#include "user_auth_proxy.h"
#include "mock_modal_callback.h"
#include "mock_remote_object.h"
#include "mock_user_auth_service.h"
#include "mock_user_access_ctrl_callback_service.h"
#include "mock_user_access_ctrl_client_callback.h"
#include "mock_user_auth_client_callback.h"
#include "mock_user_auth_callback_service.h"
#include "mock_iuser_auth_widget_callback.h"
#include "modal_callback_service.h"
#include "user_auth_callback_service.h"
#include "user_access_ctrl_callback_service.h"
#include "widget_callback_service.h"

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

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetEnrolledState001, TestSize.Level0)
{
    int32_t testApiVersion = 0;
    AuthType testAuthType = FACE;
    uint16_t credentialDigest = 23962;
    uint16_t credentialCount = 1;
    EnrolledState enrolledState;
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetEnrolledState(_, _, _))
        .Times(Exactly(1))
        .WillOnce([testApiVersion, testAuthType, credentialDigest, credentialCount](int32_t apiVersion,
            AuthType authType, EnrolledState &enrolledState) {
            EXPECT_EQ(testApiVersion, apiVersion);
            EXPECT_EQ(testAuthType, authType);
            enrolledState.credentialDigest = credentialDigest;
            enrolledState.credentialCount = credentialCount;
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    EXPECT_EQ(proxy->GetEnrolledState(testApiVersion, testAuthType, enrolledState), SUCCESS);
    EXPECT_EQ(credentialDigest, enrolledState.credentialDigest);
    EXPECT_EQ(credentialCount, enrolledState.credentialCount);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetEnrolledState002, TestSize.Level0)
{
    int32_t testApiVersion = 0;
    AuthType testAuthType = FACE;
    uint16_t credentialDigest = 23962;
    uint16_t credentialCount = 1;
    EnrolledState enrolledState;
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetEnrolledState(_, _, _))
        .Times(Exactly(1))
        .WillOnce([testApiVersion, testAuthType, credentialDigest, credentialCount](int32_t apiVersion,
            AuthType authType, EnrolledState &enrolledState) {
            EXPECT_EQ(testApiVersion, apiVersion);
            EXPECT_EQ(testAuthType, authType);
            enrolledState.credentialDigest = credentialDigest;
            enrolledState.credentialCount = credentialCount;
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            reply.WriteInt32(GENERAL_ERROR);
            return SUCCESS;
        });
    EXPECT_EQ(proxy->GetEnrolledState(testApiVersion, testAuthType, enrolledState), SUCCESS);
    EXPECT_EQ(credentialDigest, enrolledState.credentialDigest);
    EXPECT_EQ(credentialCount, enrolledState.credentialCount);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetAvailableStatus, TestSize.Level0)
{
    static const int32_t testApiVersion = 0;
    static const AuthType testAuthType = FACE;
    static const AuthTrustLevel testAuthTrustLevel = ATL3;
    static const int32_t testUserId = 100;
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetAvailableStatus(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t apiVersion, int32_t userId, AuthType authType, AuthTrustLevel authTrustLevel) {
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(2);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    EXPECT_EQ(proxy->GetAvailableStatus(testApiVersion, testUserId, testAuthType, testAuthTrustLevel), SUCCESS);
    EXPECT_EQ(proxy->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel), SUCCESS);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetProperty001, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const AuthType testAuthType = FACE;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_SCHEDULE_MODE};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback(
        new (std::nothrow) GetExecutorPropertyCallbackService(getPropCallback));
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

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetProperty002, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const AuthType testAuthType = FACE;
    std::vector<Attributes::AttributeKey> testKeys = {};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback(nullptr);
    proxy->GetProperty(testUserId, testAuthType, testKeys, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetProperty003, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const AuthType testAuthType = FACE;
    std::vector<Attributes::AttributeKey> testKeys = {};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback(
        new (std::nothrow) GetExecutorPropertyCallbackService(getPropCallback));
    proxy->GetProperty(testUserId, testAuthType, testKeys, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetProperty004, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const AuthType testAuthType = FACE;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_SCHEDULE_MODE};
    testKeys.resize(513);

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback(
        new (std::nothrow) GetExecutorPropertyCallbackService(getPropCallback));
    proxy->GetProperty(testUserId, testAuthType, testKeys, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxySetProperty001, TestSize.Level0)
{
    static const AuthType testAuthType = FACE;

    Attributes testAttr;
    EXPECT_EQ(testAttr.SetInt32Value(Attributes::ATTR_RESULT_CODE, 1), true);

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto setPropCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(setPropCallback, nullptr);
    sptr<SetExecutorPropertyCallbackInterface> testCallback(
        new (std::nothrow) SetExecutorPropertyCallbackService(setPropCallback));
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

HWTEST_F(UserAuthProxyTest, UserAuthProxySetProperty002, TestSize.Level0)
{
    static const AuthType testAuthType = FACE;

    Attributes testAttr;
    EXPECT_EQ(testAttr.SetInt32Value(Attributes::ATTR_RESULT_CODE, 1), true);

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<SetExecutorPropertyCallbackInterface> testCallback(nullptr);
    proxy->SetProperty(0, testAuthType, testAttr, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuth001, TestSize.Level0)
{
    static const int32_t testApiVersion = 0;
    static const AuthType testAuthType = FACE;
    static const AuthTrustLevel testAtl = ATL1;
    const std::vector<uint8_t> testChallenge = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(new (std::nothrow) UserAuthCallbackService(authCallback));
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
    EXPECT_EQ(proxy->Auth(testApiVersion, testChallenge, testAuthType, testAtl, testCallback), SUCCESS);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuth002, TestSize.Level0)
{
    static const int32_t testApiVersion = 0;
    static const AuthType testAuthType = FACE;
    static const AuthTrustLevel testAtl = ATL1;
    const std::vector<uint8_t> testChallenge = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(nullptr);
    EXPECT_EQ(proxy->Auth(testApiVersion, testChallenge, testAuthType, testAtl, testCallback), BAD_CONTEXT_ID);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuthUser001, TestSize.Level0)
{
    AuthParamInner testAuthParamInner = {
        .userId = 200,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL1,
    };
    std::optional<RemoteAuthParam> testRemoteAuthParam = std::nullopt;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(new (std::nothrow) UserAuthCallbackService(authCallback));
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AuthUser(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback, &testAuthParamInner](AuthParamInner &authParam,
            std::optional<RemoteAuthParam> &remoteAuthParam, sptr<UserAuthCallbackInterface> &callback) {
            EXPECT_EQ(authParam.userId, testAuthParamInner.userId);
            EXPECT_THAT(authParam.challenge, ElementsAre(1, 2, 3, 4));
            EXPECT_EQ(authParam.authType, testAuthParamInner.authType);
            EXPECT_EQ(authParam.authTrustLevel, testAuthParamInner.authTrustLevel);
            EXPECT_EQ(callback, testCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    EXPECT_EQ(proxy->AuthUser(testAuthParamInner, testRemoteAuthParam, testCallback), SUCCESS);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuthUser002, TestSize.Level0)
{
    AuthParamInner testAuthParamInner = {
        .userId = 200,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL1,
    };
    RemoteAuthParam param = {};
    param.verifierNetworkId = "123";
    param.collectorNetworkId = "1233324321423412344134";
    param.collectorTokenId = 1233;
    std::optional<RemoteAuthParam> testRemoteAuthParam = param;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(nullptr);
    EXPECT_EQ(proxy->AuthUser(testAuthParamInner, testRemoteAuthParam, testCallback), BAD_CONTEXT_ID);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuthUser003, TestSize.Level0)
{
    AuthParamInner testAuthParamInner = {
        .userId = 200,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL1,
    };
    RemoteAuthParam param = {};
    param.verifierNetworkId = "123";
    param.collectorNetworkId = "1233324321423412344134";
    param.collectorTokenId = 1233;
    std::optional<RemoteAuthParam> testRemoteAuthParam = param;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(new (std::nothrow) UserAuthCallbackService(authCallback));
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AuthUser(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback, &testAuthParamInner](AuthParamInner &authParam,
            std::optional<RemoteAuthParam> &remoteAuthParam, sptr<UserAuthCallbackInterface> &callback) {
            EXPECT_EQ(authParam.userId, testAuthParamInner.userId);
            EXPECT_THAT(authParam.challenge, ElementsAre(1, 2, 3, 4));
            EXPECT_EQ(authParam.authType, testAuthParamInner.authType);
            EXPECT_EQ(authParam.authTrustLevel, testAuthParamInner.authTrustLevel);
            EXPECT_EQ(callback, testCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    EXPECT_EQ(proxy->AuthUser(testAuthParamInner, testRemoteAuthParam, testCallback), SUCCESS);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuthUser004, TestSize.Level0)
{
    AuthParamInner testAuthParamInner = {
        .userId = 200,
        .challenge = {1, 2, 3, 4},
        .authType = FACE,
        .authTrustLevel = ATL1,
    };
    RemoteAuthParam param = {};
    param.collectorNetworkId = "1233324321423412344134";
    param.collectorTokenId = 1233;
    std::optional<RemoteAuthParam> testRemoteAuthParam = param;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(new (std::nothrow) UserAuthCallbackService(authCallback));
    EXPECT_EQ(proxy->AuthUser(testAuthParamInner, testRemoteAuthParam, testCallback), BAD_CONTEXT_ID);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyCancelAuthOrIdentify, TestSize.Level0)
{
    static const uint64_t testContextId = 200;
    static const int32_t testCancelReason = 0;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelAuthOrIdentify(_, _))
        .Times(Exactly(1))
        .WillOnce([](uint64_t contextId, int32_t cancelReason) {
            EXPECT_EQ(contextId, testContextId);
            EXPECT_EQ(cancelReason, testCancelReason);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->CancelAuthOrIdentify(testContextId, testCancelReason);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyIdentify001, TestSize.Level0)
{
    static const AuthType testAuthType = FACE;
    const std::vector<uint8_t> testChallenge = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto identifyCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(identifyCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(new (std::nothrow) UserAuthCallbackService(identifyCallback));
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
    EXPECT_EQ(proxy->Identify(testChallenge, testAuthType, testCallback), SUCCESS);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyIdentify002, TestSize.Level0)
{
    static const AuthType testAuthType = FACE;
    const std::vector<uint8_t> testChallenge = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(nullptr);
    EXPECT_EQ(proxy->Identify(testChallenge, testAuthType, testCallback), BAD_CONTEXT_ID);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuthWidget001, TestSize.Level0)
{
    static const int32_t testApiVersion = 0;
    AuthParamInner authParam;
    WidgetParamInner widgetParam;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto identifyCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(identifyCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback =
        new (std::nothrow) UserAuthCallbackService(identifyCallback);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    sptr<ModalCallbackInterface> testModalCallback = new MockModalCallback();
    EXPECT_NE(testModalCallback, nullptr);
    auto *mockModalCallback = static_cast<MockModalCallback *>(testModalCallback.GetRefPtr());
    EXPECT_NE(mockModalCallback, nullptr);
    EXPECT_CALL(*mockModalCallback, SendCommand(_, _)).Times(0);
    EXPECT_CALL(*service, AuthWidget(_, _, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback, &testModalCallback](int32_t apiVersion, const AuthParamInner &authParam,
            const WidgetParamInner &widgetParam, sptr<UserAuthCallbackInterface> &callback,
            sptr<ModalCallbackInterface> &modalCallback) {
            EXPECT_EQ(apiVersion, testApiVersion);
            EXPECT_EQ(callback, testCallback);
            EXPECT_EQ(modalCallback, testModalCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->AuthWidget(testApiVersion, authParam, widgetParam, testCallback, testModalCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuthWidget002, TestSize.Level0)
{
    static const int32_t testApiVersion = 0;
    AuthParamInner authParam;
    WidgetParamInner widgetParam;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(nullptr);
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    proxy->AuthWidget(testApiVersion, authParam, widgetParam, testCallback, testModalCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyAuthWidget003, TestSize.Level0)
{
    static const int32_t testApiVersion = 0;
    AuthParamInner authParam;
    authParam.authTypes.push_back(PIN);
    authParam.reuseUnlockResult.isReuse = true;
    WidgetParamInner widgetParam;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto identifyCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(identifyCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback =
        new (std::nothrow) UserAuthCallbackService(identifyCallback);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    sptr<ModalCallbackInterface> testModalCallback = new MockModalCallback();
    EXPECT_NE(testModalCallback, nullptr);
    auto *mockModalCallback = static_cast<MockModalCallback *>(testModalCallback.GetRefPtr());
    EXPECT_NE(mockModalCallback, nullptr);
    EXPECT_CALL(*mockModalCallback, SendCommand(_, _)).Times(0);
    EXPECT_CALL(*service, AuthWidget(_, _, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback, &testModalCallback](int32_t apiVersion, const AuthParamInner &authParam,
            const WidgetParamInner &widgetParam, sptr<UserAuthCallbackInterface> &callback,
            sptr<ModalCallbackInterface> &modalCallback) {
            EXPECT_EQ(apiVersion, testApiVersion);
            EXPECT_EQ(callback, testCallback);
            EXPECT_EQ(modalCallback, testModalCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    EXPECT_EQ(proxy->AuthWidget(testApiVersion, authParam, widgetParam, testCallback, testModalCallback), SUCCESS);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyNotice001, TestSize.Level0)
{
    static const NoticeType testNoticeType = NoticeType::WIDGET_NOTICE;
    static const std::string testEventData = "notice";

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Notice(_, _))
        .Times(Exactly(1))
        .WillOnce([](NoticeType noticeType, const std::string &eventData) {
            EXPECT_EQ(noticeType, testNoticeType);
            EXPECT_EQ(eventData, testEventData);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->Notice(testNoticeType, testEventData);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyRegisterWidgetCallback001, TestSize.Level0)
{
    static const int32_t testVersion = 0;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto identifyCallback = Common::MakeShared<MockIUserAuthWidgetCallback>();
    EXPECT_NE(identifyCallback, nullptr);
    sptr<WidgetCallbackInterface> testCallback =
        new (std::nothrow) WidgetCallbackService(identifyCallback);
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterWidgetCallback(_, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t version, sptr<WidgetCallbackInterface> &callback) {
            EXPECT_EQ(version, testVersion);
            EXPECT_EQ(callback, testCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->RegisterWidgetCallback(testVersion, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyRegisterWidgetCallback002, TestSize.Level0)
{
    static const int32_t testVersion = 0;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<WidgetCallbackInterface> callback(nullptr);
    EXPECT_EQ(proxy->RegisterWidgetCallback(testVersion, callback), GENERAL_ERROR);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyRegistUserAuthSuccessEventListener001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    sptr<AuthEventListenerInterface> testCallback = new (std::nothrow) MockAuthEventListenerService();
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegistUserAuthSuccessEventListener(_, _))
        .Times(Exactly(1))
        .WillOnce([](const std::vector<AuthType> &authType, const sptr<AuthEventListenerInterface> &callback) {
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);
    proxy->RegistUserAuthSuccessEventListener(authTypeList, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyRegistUserAuthSuccessEventListener002, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);
    EXPECT_EQ(proxy->RegistUserAuthSuccessEventListener(authTypeList, nullptr), GENERAL_ERROR);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyUnRegistUserAuthSuccessEventListener001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    sptr<AuthEventListenerInterface> testCallback = new (std::nothrow) MockAuthEventListenerService();
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UnRegistUserAuthSuccessEventListener(_))
        .Times(Exactly(1))
        .WillOnce([](const sptr<AuthEventListenerInterface> &callback) {
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->UnRegistUserAuthSuccessEventListener(testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyUnRegistUserAuthSuccessEventListener002, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    EXPECT_EQ(proxy->UnRegistUserAuthSuccessEventListener(nullptr), GENERAL_ERROR);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxySetGlobalConfigParam001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    GlobalConfigParam param = {};
    EXPECT_EQ(proxy->SetGlobalConfigParam(param), INVALID_PARAMETERS);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxySetGlobalConfigParam002, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetGlobalConfigParam(_))
        .Times(Exactly(1))
        .WillOnce([](const GlobalConfigParam &param) {
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return GENERAL_ERROR;
        });
    GlobalConfigParam param = {};
    param.type = PIN_EXPIRED_PERIOD;
    param.value.pinExpiredPeriod = 1;
    EXPECT_EQ(proxy->SetGlobalConfigParam(param), GENERAL_ERROR);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxySetGlobalConfigParam003, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetGlobalConfigParam(_))
        .Times(Exactly(1))
        .WillOnce([](const GlobalConfigParam &param) {
            return GENERAL_ERROR;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    GlobalConfigParam param = {};
    param.type = ENABLE_STATUS;
    param.value.enableStatus = true;
    EXPECT_EQ(proxy->SetGlobalConfigParam(param), GENERAL_ERROR);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetPropertyById001, TestSize.Level0)
{
    static const uint64_t testCredentialId = 1;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_SCHEDULE_MODE};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback(
        new (std::nothrow) GetExecutorPropertyCallbackService(getPropCallback));
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetPropertyById(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](uint64_t credentialId,
            const std::vector<Attributes::AttributeKey> &keys, sptr<GetExecutorPropertyCallbackInterface> &callback) {
            EXPECT_EQ(credentialId, testCredentialId);
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
    proxy->GetPropertyById(testCredentialId, testKeys, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetPropertyById002, TestSize.Level0)
{
    static const uint64_t testCredentialId = 1;
    std::vector<Attributes::AttributeKey> testKeys = {};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback(nullptr);
    proxy->GetPropertyById(testCredentialId, testKeys, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyGetPropertyById003, TestSize.Level0)
{
    static const uint64_t testCredentialId = 1;
    std::vector<Attributes::AttributeKey> testKeys = {};

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback(
        new (std::nothrow) GetExecutorPropertyCallbackService(getPropCallback));
    proxy->GetPropertyById(testCredentialId, testKeys, testCallback);
}


HWTEST_F(UserAuthProxyTest, UserAuthProxyGetPropertyById004, TestSize.Level0)
{
    static const uint64_t testCredentialId = 1;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_SCHEDULE_MODE};
    testKeys.resize(513);

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    sptr<GetExecutorPropertyCallbackInterface> testCallback(
        new (std::nothrow) GetExecutorPropertyCallbackService(getPropCallback));
    proxy->GetPropertyById(testCredentialId, testKeys, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyPrepareRemoteAuth001, TestSize.Level0)
{
    const std::string networkId = "123456";

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(new (std::nothrow) UserAuthCallbackService(authCallback));
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, PrepareRemoteAuth(_, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](const std::string &networkId, sptr<UserAuthCallbackInterface> &callback) {
            EXPECT_EQ(callback, testCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    EXPECT_EQ(proxy->PrepareRemoteAuth(networkId, testCallback), SUCCESS);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyPrepareRemoteAuth002, TestSize.Level0)
{
    const std::string networkId = "123456";

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(nullptr);
    EXPECT_EQ(proxy->PrepareRemoteAuth(networkId, testCallback), GENERAL_ERROR);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyPrepareRemoteAuth003, TestSize.Level0)
{
    const std::string networkId = "123456";

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    sptr<UserAuthCallbackInterface> testCallback(new (std::nothrow) UserAuthCallbackService(authCallback));
    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, PrepareRemoteAuth(_, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](const std::string &networkId, sptr<UserAuthCallbackInterface> &callback) {
            EXPECT_EQ(callback, testCallback);
            return 0;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return GENERAL_ERROR;
        });
    EXPECT_EQ(proxy->PrepareRemoteAuth(networkId, testCallback), GENERAL_ERROR);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyVerifyAuthToken001, TestSize.Level0)
{
    std::vector<uint8_t> testTokenIn = {};
    uint64_t testAllowableDuration = 0;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    auto callback = Common::MakeShared<MockVerifyTokenCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<VerifyTokenCallbackInterface> testCallback =
        new (std::nothrow) VerifyTokenCallbackService(callback);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, VerifyAuthToken(_, _, _)).Times(Exactly(1));
    ON_CALL(*service, VerifyAuthToken)
        .WillByDefault(
            [&testTokenIn, &testAllowableDuration, &testCallback]
            (const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
                const sptr<VerifyTokenCallbackInterface> &callback) {
                EXPECT_EQ(testTokenIn, tokenIn);
                EXPECT_EQ(testAllowableDuration, allowableDuration);
            }
        );

    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->VerifyAuthToken(testTokenIn, testAllowableDuration, testCallback);
}

HWTEST_F(UserAuthProxyTest, UserAuthProxyVerifyAuthToken002, TestSize.Level0)
{
    std::vector<uint8_t> testTokenIn = {};
    uint64_t testAllowableDuration = 0;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    sptr<VerifyTokenCallbackInterface> testCallback = new (std::nothrow) VerifyTokenCallbackService(nullptr);
    proxy->VerifyAuthToken(testTokenIn, testAllowableDuration, testCallback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS