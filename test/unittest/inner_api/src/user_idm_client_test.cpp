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

#include "accesstoken_kit.h"
#include "file_ex.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "iam_ptr.h"
#include "mock_user_idm_client_callback.h"
#include "user_idm_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

static uint64_t tokenId;

void UserIdmClientTest::SetUpTestCase()
{
    static const char *PERMS[] = {
        "ohos.permission.MANAGE_USER_IDM",
        "ohos.permission.USE_USER_IDM",
        "ohos.permission.ENFORCE_USER_IDM"
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 3,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = PERMS,
        .acls = nullptr,
        .processName = "user_idm_client_test",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    SaveStringToFile("/sys/fs/selinux/enforce", "0");
}

void UserIdmClientTest::TearDownTestCase()
{
    Security::AccessToken::AccessTokenKit::DeleteToken(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    SaveStringToFile("/sys/fs/selinux/enforce", "1");
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
    std::vector<uint8_t> challenge = UserIdmClient::GetInstance().OpenSession(testUserId);
    UserIdmClient::GetInstance().CloseSession(testUserId);
}

HWTEST_F(UserIdmClientTest, UserIdmClientCloseSession, TestSize.Level0)
{
    int32_t testUserId = 200;
    UserIdmClient::GetInstance().CloseSession(testUserId);
}

HWTEST_F(UserIdmClientTest, UserIdmClientAddCredential, TestSize.Level0)
{
    int32_t testUserId = 200;
    CredentialParameters testPara = {};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserIdmClient::GetInstance().AddCredential(testUserId, testPara, testCallback);
}

HWTEST_F(UserIdmClientTest, UserIdmClientUpdateCredential, TestSize.Level0)
{
    int32_t testUserId = 200;
    CredentialParameters testPara = {};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserIdmClient::GetInstance().UpdateCredential(testUserId, testPara, testCallback);
}

HWTEST_F(UserIdmClientTest, UserIdmClientCancel, TestSize.Level0)
{
    int32_t testUserId = 200;
    int32_t ret = UserIdmClient::GetInstance().Cancel(testUserId);
    EXPECT_NE(ret, SUCCESS);
}

HWTEST_F(UserIdmClientTest, UserIdmClientDeleteCredential, TestSize.Level0)
{
    int32_t testUserId = 200;
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserIdmClient::GetInstance().DeleteCredential(testUserId, testCredentialId, testAuthToken, testCallback);
}

HWTEST_F(UserIdmClientTest, UserIdmClientDeleteUser, TestSize.Level0)
{
    int32_t testUserId = 200;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserIdmClient::GetInstance().DeleteUser(testUserId, testAuthToken, testCallback);
}

HWTEST_F(UserIdmClientTest, UserIdmClientEraseUser, TestSize.Level0)
{
    int32_t testUserId = 200;
    auto testCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    int32_t ret = UserIdmClient::GetInstance().EraseUser(testUserId, testCallback);
    EXPECT_NE(ret, SUCCESS);
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetCredentialInfo, TestSize.Level0)
{
    int32_t testUserId = 200;
    AuthType testAuthType = PIN;
    auto testCallback = Common::MakeShared<MockGetCredentialInfoCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnCredentialInfo(_)).Times(1);
    int32_t ret = UserIdmClient::GetInstance().GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_NE(ret, SUCCESS);
}

HWTEST_F(UserIdmClientTest, UserIdmClientGetSecUserInfo, TestSize.Level0)
{
    int32_t testUserId = 200;
    auto testCallback = Common::MakeShared<MockGetSecUserInfoCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnSecUserInfo(_)).Times(0);
    int32_t ret = UserIdmClient::GetInstance().GetSecUserInfo(testUserId, testCallback);
    EXPECT_NE(ret, SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS