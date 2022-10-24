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

#include "user_idm_client_test.h"

#include "iam_ptr.h"
#include "mock_ipc_client_utils.h"
#include "mock_remote_object.h"
#include "mock_user_idm_client_callback.h"
#include "mock_user_idm_service.h"
#include "user_idm_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmClientTest::SetUpTestCase()
{
}

void UserIdmClientTest::TearDownTestCase()
{
}

void UserIdmClientTest::SetUp()
{
}

void UserIdmClientTest::TearDown()
{
}

HWTEST_F(UserIdmClientTest, UserIdmClientOpenSession, TestSize.Level0)
{
    int32_t testUserId = 21200;
    std::vector<uint8_t> testChallenge = {1, 3, 4, 7};

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OpenSession(_, _)).Times(1);
    ON_CALL(*service, OpenSession)
        .WillByDefault(
            [&testUserId, &testChallenge](int32_t userId, std::vector<uint8_t> &challenge) {
                EXPECT_EQ(userId, testUserId);
                challenge = testChallenge;
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

    std::vector<uint8_t> challenge = UserIdmClient::GetInstance().OpenSession(testUserId);
    EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientCloseSession, TestSize.Level0)
{
    int32_t testUserId = 200;

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, CloseSession(_)).Times(1);
    ON_CALL(*service, CloseSession)
        .WillByDefault(
            [&testUserId](int32_t userId) {
                EXPECT_EQ(userId, testUserId);
                return;
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
    
    UserIdmClient::GetInstance().CloseSession(testUserId);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientAddCredential, TestSize.Level0)
{
    int32_t testUserId = 200;
    CredentialParameters testPara = {};
    testPara.authType = FACE;
    testPara.pinType = std::nullopt;
    testPara.token = {1, 4, 7, 0};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, AddCredential(_, _, _, _, _, _)).Times(1);
    ON_CALL(*service, AddCredential)
        .WillByDefault(
            [&testUserId, &testPara](int32_t userId, AuthType authType, PinSubType pinSubType,
                const std::vector<uint8_t> &token, const sptr<IdmCallbackInterface> &callback, bool isUpdate) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testPara.authType);
                EXPECT_THAT(token, ElementsAreArray(testPara.token));
                EXPECT_EQ(isUpdate, false);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
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

    UserIdmClient::GetInstance().AddCredential(testUserId, testPara, testCallback);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientUpdateCredential, TestSize.Level0)
{
    int32_t testUserId = 200;
    CredentialParameters testPara = {};
    testPara.authType = PIN;
    testPara.pinType = PIN_SIX;
    testPara.token = {1, 4, 7, 0};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, UpdateCredential(_, _, _, _, _)).Times(1);
    ON_CALL(*service, UpdateCredential)
        .WillByDefault(
            [&testUserId, &testPara](int32_t userId, AuthType authType, PinSubType pinSubType,
                const std::vector<uint8_t> &token, const sptr<IdmCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testPara.authType);
                EXPECT_TRUE(testPara.pinType.has_value());
                EXPECT_EQ(pinSubType, testPara.pinType.value());
                EXPECT_THAT(token, ElementsAreArray(testPara.token));
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
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

    UserIdmClient::GetInstance().UpdateCredential(testUserId, testPara, testCallback);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientCancel, TestSize.Level0)
{
    int32_t testUserId = 200;

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, Cancel(_)).Times(1);
    ON_CALL(*service, Cancel)
        .WillByDefault(
            [&testUserId](int32_t userId) {
                EXPECT_EQ(userId, testUserId);
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

    int32_t ret = UserIdmClient::GetInstance().Cancel(testUserId);
    EXPECT_EQ(ret, SUCCESS);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientDeleteCredential, TestSize.Level0)
{
    int32_t testUserId = 200;
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DelCredential(_, _, _, _)).Times(1);
    ON_CALL(*service, DelCredential)
        .WillByDefault(
            [&testUserId, &testCredentialId, &testAuthToken](int32_t userId, uint64_t credentialId,
                const std::vector<uint8_t> &authToken, const sptr<IdmCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(credentialId, testCredentialId);
                EXPECT_THAT(authToken, ElementsAreArray(testAuthToken));
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
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

    UserIdmClient::GetInstance().DeleteCredential(testUserId, testCredentialId, testAuthToken, testCallback);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientDeleteUser, TestSize.Level0)
{
    int32_t testUserId = 200;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, DelUser(_, _, _)).Times(1);
    ON_CALL(*service, DelUser)
        .WillByDefault(
            [&testUserId, &testAuthToken](int32_t userId, const std::vector<uint8_t> authToken,
                const sptr<IdmCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_THAT(authToken, ElementsAreArray(testAuthToken));
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
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

    UserIdmClient::GetInstance().DeleteUser(testUserId, testAuthToken, testCallback);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientEraseUser, TestSize.Level0)
{
    int32_t testUserId = 200;
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, EnforceDelUser(_, _)).Times(1);
    ON_CALL(*service, EnforceDelUser)
        .WillByDefault(
            [&testUserId](int32_t userId, const sptr<IdmCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                if (callback != nullptr) {
                    Attributes extraInfo;
                    callback->OnResult(SUCCESS, extraInfo);
                }
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

    int32_t ret = UserIdmClient::GetInstance().EraseUser(testUserId, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetCredentialInfo, TestSize.Level0)
{
    int32_t testUserId = 200;
    AuthType testAuthType = PIN;
    auto testCallback = Common::MakeShared<MockGetCredentialInfoCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnCredentialInfo(_)).Times(1);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetCredentialInfo(_, _, _)).Times(1);
    ON_CALL(*service, GetCredentialInfo)
        .WillByDefault(
            [&testUserId, &testAuthType](int32_t userId, AuthType authType,
                const sptr<IdmGetCredInfoCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_EQ(authType, testAuthType);
                if (callback != nullptr) {
                    callback->OnCredentialInfos({}, std::nullopt);
                }
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

    int32_t ret = UserIdmClient::GetInstance().GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    IpcClientUtils::ResetObj();
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetSecUserInfo, TestSize.Level0)
{
    int32_t testUserId = 200;
    auto testCallback = Common::MakeShared<MockGetSecUserInfoCallback>();
    EXPECT_NE(testCallback, nullptr);

    auto service = Common::MakeShared<MockUserIdmService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, GetSecInfo(_, _)).Times(1);
    ON_CALL(*service, GetSecInfo)
        .WillByDefault(
            [&testUserId](int32_t userId, const sptr<IdmGetSecureUserInfoCallbackInterface> &callback) {
                EXPECT_EQ(userId, testUserId);
                EXPECT_NE(callback, nullptr);
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

    int32_t ret = UserIdmClient::GetInstance().GetSecUserInfo(testUserId, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    IpcClientUtils::ResetObj();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS