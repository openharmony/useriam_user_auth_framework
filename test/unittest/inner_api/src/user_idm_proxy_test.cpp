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

#include "user_idm_proxy_test.h"

#include "iam_ptr.h"
#include "user_idm_proxy.h"
#include "mock_remote_object.h"
#include "mock_user_idm_service.h"
#include "mock_user_idm_client_callback.h"
#include "user_idm_callback_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmProxyTest::SetUpTestCase()
{
}

void UserIdmProxyTest::TearDownTestCase()
{
}

void UserIdmProxyTest::SetUp()
{
}

void UserIdmProxyTest::TearDown()
{
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyOpenSession, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    std::vector<uint8_t> testChallenge;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OpenSession(_, _))
        .Times(Exactly(1))
        .WillOnce([](int32_t userId, std::vector<uint8_t> &challenge) {
            EXPECT_EQ(testUserId, userId);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->OpenSession(testUserId, testChallenge);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyCloseSession, TestSize.Level0)
{
    static const int32_t testUserId = 200;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CloseSession(_))
        .Times(Exactly(1))
        .WillOnce([](int32_t userId) {
            EXPECT_EQ(testUserId, userId);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->CloseSession(testUserId);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyGetCredentialInfo, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const AuthType testAuthType = PIN;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getCredInfoCallback = Common::MakeShared<MockGetCredentialInfoCallback>();
    EXPECT_NE(getCredInfoCallback, nullptr);
    sptr<IdmGetCredInfoCallbackInterface> testCallback =
        new (std::nothrow) IdmGetCredInfoCallbackService(getCredInfoCallback);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetCredentialInfo(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t userId, AuthType authType,
            const sptr<IdmGetCredInfoCallbackInterface> &callback) {
            EXPECT_EQ(testUserId, userId);
            EXPECT_EQ(testAuthType, authType);
            EXPECT_EQ(testCallback, callback);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->GetCredentialInfo(testUserId, testAuthType, testCallback);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyGetSecInfo, TestSize.Level0)
{
    static const int32_t testUserId = 200;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto getSecInfoCallback = Common::MakeShared<MockGetSecUserInfoCallback>();
    EXPECT_NE(getSecInfoCallback, nullptr);
    sptr<IdmGetSecureUserInfoCallbackInterface> testCallback =
        new (std::nothrow) IdmGetSecureUserInfoCallbackService(getSecInfoCallback);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetSecInfo(_, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t userId, const sptr<IdmGetSecureUserInfoCallbackInterface> &callback) {
            EXPECT_EQ(testUserId, userId);
            EXPECT_EQ(testCallback, callback);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->GetSecInfo(testUserId, testCallback);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyAddCredential, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = FACE;
    testCredPara.pinType = PIN_SIX;
    testCredPara.token = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto idmCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(idmCallback, nullptr);
    sptr<IdmCallbackInterface> testCallback = new (std::nothrow) IdmCallbackService(idmCallback);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AddCredential(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCredPara](int32_t userId, const UserIdmInterface::CredentialPara &credPara,
            const sptr<IdmCallbackInterface> &callback, bool isUpdate) {
            EXPECT_EQ(userId, testUserId);
            EXPECT_EQ(credPara.authType, testCredPara.authType);
            EXPECT_EQ(credPara.pinType, testCredPara.pinType);
            EXPECT_THAT(credPara.token, ElementsAreArray(testCredPara.token));
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->AddCredential(testUserId, testCredPara, testCallback, false);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyUpdateCredential, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = FACE;
    testCredPara.pinType = PIN_SIX;
    testCredPara.token = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto idmCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(idmCallback, nullptr);
    sptr<IdmCallbackInterface> testCallback = new (std::nothrow) IdmCallbackService(idmCallback);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdateCredential(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCredPara](int32_t userId, const UserIdmInterface::CredentialPara &credPara,
            const sptr<IdmCallbackInterface> &callback) {
            EXPECT_EQ(userId, testUserId);
            EXPECT_EQ(credPara.authType, testCredPara.authType);
            EXPECT_EQ(credPara.pinType, testCredPara.pinType);
            EXPECT_THAT(credPara.token, ElementsAreArray(testCredPara.token));
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->UpdateCredential(testUserId, testCredPara, testCallback);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyCancel, TestSize.Level0)
{
    static const int32_t testUserId = 200;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Cancel(_))
        .Times(Exactly(1))
        .WillOnce([](int32_t userId) {
            EXPECT_EQ(testUserId, userId);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->Cancel(testUserId);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyEnforceDelUser, TestSize.Level0)
{
    static const int32_t testUserId = 200;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto idmCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(idmCallback, nullptr);
    sptr<IdmCallbackInterface> testCallback = new (std::nothrow) IdmCallbackService(idmCallback);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, EnforceDelUser(_, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t userId, const sptr<IdmCallbackInterface> &callback) {
            EXPECT_EQ(testUserId, userId);
            EXPECT_EQ(testCallback, callback);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->EnforceDelUser(testUserId, testCallback);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyDelUser, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto idmCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(idmCallback, nullptr);
    sptr<IdmCallbackInterface> testCallback = new (std::nothrow) IdmCallbackService(idmCallback);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DelUser(_, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t userId, const std::vector<uint8_t> authToken,
            const sptr<IdmCallbackInterface> &callback) {
            EXPECT_EQ(testUserId, userId);
            EXPECT_THAT(testAuthToken, ElementsAre(1, 2, 3, 4));
            EXPECT_EQ(testCallback, callback);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->DelUser(testUserId, testAuthToken, testCallback);
}

HWTEST_F(UserIdmProxyTest, UserIdmProxyDelCredential, TestSize.Level0)
{
    static const int32_t testUserId = 200;
    static const uint64_t testCredentialId = 300;
    static const std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<UserIdmProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto idmCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(idmCallback, nullptr);
    sptr<IdmCallbackInterface> testCallback = new (std::nothrow) IdmCallbackService(idmCallback);
    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DelCredential(_, _, _, _))
        .Times(Exactly(1))
        .WillOnce([&testCallback](int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
            const sptr<IdmCallbackInterface> &callback) {
            EXPECT_EQ(testUserId, userId);
            EXPECT_EQ(testCredentialId, credentialId);
            EXPECT_THAT(testAuthToken, ElementsAre(1, 2, 3, 4));
            EXPECT_EQ(testCallback, callback);
            return SUCCESS;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    proxy->DelCredential(testUserId, testCredentialId, testAuthToken, testCallback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS