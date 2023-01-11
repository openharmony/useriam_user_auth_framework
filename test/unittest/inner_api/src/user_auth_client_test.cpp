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

#include "user_auth_client_test.h"

#include "iam_ptr.h"
#include "user_auth_client.h"
#include "user_auth_client_impl.h"
#include "mock_ipc_client_utils.h"
#include "mock_remote_object.h"
#include "mock_user_auth_service.h"
#include "mock_user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthClientTest::SetUpTestCase()
{
}

void UserAuthClientTest::TearDownTestCase()
{
}

void UserAuthClientTest::SetUp()
{
}

void UserAuthClientTest::TearDown()
{
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetAvailableStatus001, TestSize.Level0)
{
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL1;

    IpcClientUtils::ResetObj();
    int32_t ret = UserAuthClientImpl::Instance().GetAvailableStatus(testAuthType, testAtl);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetAvailableStatus002, TestSize.Level0)
{
    int32_t testApiVersion = 9;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL1;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetAvailableStatus(_, _, _)).Times(1);
    ON_CALL(*service, GetAvailableStatus)
        .WillByDefault(
            [&testApiVersion, &testAuthType, &testAtl](int32_t apiVersion, AuthType authType,
                AuthTrustLevel authTrustLevel) {
                EXPECT_EQ(apiVersion, testApiVersion);
                EXPECT_EQ(authType, testAuthType);
                EXPECT_EQ(authTrustLevel, testAtl);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
    int32_t ret = UserAuthClientImpl::Instance().GetAvailableStatus(testApiVersion, testAuthType, testAtl);
    EXPECT_EQ(ret, SUCCESS);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetProperty001, TestSize.Level0)
{
    int32_t testUserId = 200;
    GetPropertyRequest testRequest = {};

    std::shared_ptr<MockGetPropCallback> testCallback = nullptr;
    UserAuthClient::GetInstance().GetProperty(testUserId, testRequest, testCallback);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().GetProperty(testUserId, testRequest, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetProperty002, TestSize.Level0)
{
    int32_t testUserId = 200;
    GetPropertyRequest testRequest = {};
    testRequest.authType = FACE;
    testRequest.keys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE};

    auto testCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetProperty(_, _, _, _)).Times(1);
    ON_CALL(*service, GetProperty)
        .WillByDefault(
            [&testUserId, &testRequest](int32_t userId, AuthType authType,
                const std::vector<Attributes::AttributeKey> &keys,
                sptr<GetExecutorPropertyCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testRequest.authType);
                EXPECT_THAT(keys, ElementsAreArray(testRequest.keys));
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnGetExecutorPropertyResult(SUCCESS, extraInfo);
                }
            }
        );
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
    UserAuthClient::GetInstance().GetProperty(testUserId, testRequest, testCallback);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetProperty001, TestSize.Level0)
{
    int32_t testUserId = 200;
    SetPropertyRequest testRequest = {};
    std::shared_ptr<MockSetPropCallback> testCallback = nullptr;
    UserAuthClient::GetInstance().SetProperty(testUserId, testRequest, testCallback);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().SetProperty(testUserId, testRequest, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetProperty002, TestSize.Level0)
{
    int32_t testUserId = 200;
    SetPropertyRequest testRequest = {};
    testRequest.authType = PIN;
    testRequest.mode = PROPERTY_MODE_DEL;
    EXPECT_EQ(testRequest.attrs.SetInt32Value(Attributes::ATTR_RESULT_CODE, FAIL), true);
    auto testCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SetProperty(_, _, _, _)).Times(1);
    ON_CALL(*service, SetProperty)
        .WillByDefault(
            [&testUserId, &testRequest](int32_t userId, AuthType authType, const Attributes &attributes,
                sptr<SetExecutorPropertyCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testRequest.authType);
                int32_t resultCode;
                EXPECT_EQ(attributes.GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode), true);
                EXPECT_EQ(resultCode, FAIL);
                if (callback != nullptr) {
                    callback->OnSetExecutorPropertyResult(SUCCESS);
                }
            }
        );
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });

    UserAuthClient::GetInstance().SetProperty(testUserId, testRequest, testCallback);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginNorthAuthentication001, TestSize.Level0)
{
    int32_t testApiVersion = 8;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4, 3, 2, 1, 0};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAtl = ATL1;
    std::shared_ptr<MockAuthenticationCallback> testCallback = nullptr;
    uint64_t contextId = UserAuthClientImpl::Instance().BeginNorthAuthentication(testApiVersion, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, 0);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    contextId = UserAuthClientImpl::Instance().BeginNorthAuthentication(testApiVersion, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginNorthAuthentication002, TestSize.Level0)
{
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4, 3, 2, 1, 0};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAtl = ATL1;
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    uint64_t testContextId = 15858;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Auth(_, _, _, _, _)).Times(1);
    ON_CALL(*service, Auth)
        .WillByDefault(
            [&testApiVersion, &testChallenge, &testAuthType, &testAtl, &testContextId](int32_t apiVersion,
                const std::vector<uint8_t> &challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_EQ(apiVersion, testApiVersion);
                EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
                EXPECT_EQ(authType, testAuthType);
                EXPECT_EQ(authTrustLevel, testAtl);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
                }
                return testContextId;
            }
        );
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });

    uint64_t contextId = UserAuthClientImpl::Instance().BeginNorthAuthentication(testApiVersion, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, testContextId);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginAuthentication001, TestSize.Level0)
{
    int32_t testUserId = 84548;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4, 8, 7, 5, 4};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAtl = ATL1;
    std::shared_ptr<MockAuthenticationCallback> testCallback = nullptr;
    uint64_t contextId = UserAuthClient::GetInstance().BeginAuthentication(testUserId, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, 0);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    contextId = UserAuthClient::GetInstance().BeginAuthentication(testUserId, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginAuthentication002, TestSize.Level0)
{
    int32_t testUserId = 84548;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4, 8, 7, 5, 4};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAtl = ATL1;
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    uint64_t testContextId = 15858;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AuthUser(_, _, _, _, _)).Times(1);
    ON_CALL(*service, AuthUser)
        .WillByDefault(
            [&testUserId, &testChallenge, &testAuthType, &testAtl, &testContextId](int32_t userId,
                const std::vector<uint8_t> &challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
                EXPECT_EQ(authType, testAuthType);
                EXPECT_EQ(authTrustLevel, testAtl);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
                }
                return testContextId;
            }
        );
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });

    uint64_t contextId = UserAuthClient::GetInstance().BeginAuthentication(testUserId, testChallenge,
        testAuthType, testAtl, testCallback);
    EXPECT_EQ(contextId, testContextId);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelAuthentication001, TestSize.Level0)
{
    uint64_t testContextId = 12345562;

    IpcClientUtils::ResetObj();
    int32_t ret = UserAuthClient::GetInstance().CancelAuthentication(testContextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelAuthentication002, TestSize.Level0)
{
    uint64_t testContextId = 12345562;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelAuthOrIdentify(_)).Times(1);
    ON_CALL(*service, CancelAuthOrIdentify)
        .WillByDefault(
            [&testContextId](uint64_t contextId) {
                EXPECT_EQ(contextId, testContextId);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });

    int32_t ret = UserAuthClient::GetInstance().CancelAuthentication(testContextId);
    EXPECT_EQ(ret, SUCCESS);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginIdentification001, TestSize.Level0)
{
    std::vector<uint8_t> testChallenge = {4, 5, 6, 7, 3, 4, 1, 2};
    AuthType testAuthType = FACE;
    std::shared_ptr<MockIdentificationCallback> testCallback = nullptr;
    uint64_t contextId = UserAuthClient::GetInstance().BeginIdentification(testChallenge, testAuthType, testCallback);
    EXPECT_EQ(contextId, 0);

    IpcClientUtils::ResetObj();
    testCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    contextId = UserAuthClient::GetInstance().BeginIdentification(testChallenge, testAuthType, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginIdentification002, TestSize.Level0)
{
    std::vector<uint8_t> testChallenge = {4, 5, 6, 7, 3, 4, 1, 2};
    AuthType testAuthType = FACE;
    auto testCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    uint64_t testContextId = 548781;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Identify(_, _, _)).Times(1);
    ON_CALL(*service, Identify)
        .WillByDefault(
            [&testChallenge, &testAuthType, &testContextId](const std::vector<uint8_t> &challenge,
                AuthType authType, sptr<UserAuthCallbackInterface> &callback) {
                EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
                EXPECT_EQ(authType, testAuthType);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
                }
                return testContextId;
            }
        );
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });

    uint64_t contextId = UserAuthClient::GetInstance().BeginIdentification(testChallenge, testAuthType, testCallback);
    EXPECT_EQ(contextId, testContextId);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelIdentification001, TestSize.Level0)
{
    uint64_t testContextId = 1221215;
    
    IpcClientUtils::ResetObj();
    int32_t ret = UserAuthClient::GetInstance().CancelIdentification(testContextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelIdentification002, TestSize.Level0)
{
    uint64_t testContextId = 1221215;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CancelAuthOrIdentify(_)).Times(1);
    ON_CALL(*service, CancelAuthOrIdentify)
        .WillByDefault(
            [&testContextId](uint64_t contextId) {
                EXPECT_EQ(contextId, testContextId);
                return SUCCESS;
            }
        );
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
    
    int32_t ret = UserAuthClient::GetInstance().CancelIdentification(testContextId);
    EXPECT_EQ(ret, SUCCESS);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetVersion001, TestSize.Level0)
{
    IpcClientUtils::ResetObj();
    int32_t version = -1;
    int32_t ret = UserAuthClientImpl::Instance().GetVersion(version);
    EXPECT_EQ(ret, GENERAL_ERROR);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetVersion002, TestSize.Level0)
{
    int32_t testVersion = 20000;

    auto service = Common::MakeShared<MockUserAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetVersion(_)).Times(1);
    ON_CALL(*service, GetVersion)
        .WillByDefault(
            [&testVersion](int32_t &version) {
                version = testVersion;
                return SUCCESS;
            }
        );

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    IpcClientUtils::SetObj(obj);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
    int32_t version;
    int32_t result = UserAuthClientImpl::Instance().GetVersion(version);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(version, testVersion);
    IpcClientUtils::ResetObj();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS