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

#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "iam_ptr.h"
#include "user_auth_client.h"
#include "user_auth_client_impl.h"
#include "mock_user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthClientTest::SetUpTestCase()
{
    static const char *PERMS[] = {
        "ohos.permission.ACCESS_USER_AUTH_INTERNAL",
        "ohos.permission.ACCESS_BIOMETRIC"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = PERMS,
        .acls = nullptr,
        .processName = "useriam",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
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

HWTEST_F(UserAuthClientTest, UserAuthClientGetAvailableStatus, TestSize.Level0)
{
    AuthType testAuthType = FACE;
    AuthTrustLevel testAtl = ATL1;
    int32_t ret = UserAuthClientImpl::Instance().GetAvailableStatus(testAuthType, testAtl);
    EXPECT_NE(ret, SUCCESS);
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetProperty, TestSize.Level0)
{
    int32_t testUserId = 200;
    GetPropertyRequest testRequest = {};
    auto testCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().GetProperty(testUserId, testRequest, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientSetProperty, TestSize.Level0)
{
    int32_t testUserId = 200;
    SetPropertyRequest testRequest = {};
    auto testCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().SetProperty(testUserId, testRequest, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginAuthentication001, TestSize.Level0)
{
    int32_t testUserId = 200;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAtl = ATL1;
    SetPropertyRequest testRequest = {};
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().BeginAuthentication(testUserId, testChallenge, testAuthType, testAtl, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginAuthentication002, TestSize.Level0)
{
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAtl = ATL1;
    SetPropertyRequest testRequest = {};
    auto testCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClientImpl::Instance().BeginAuthentication(testChallenge, testAuthType, testAtl, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelAuthentication, TestSize.Level0)
{
    uint64_t testContextId = 122;
    int32_t ret = UserAuthClient::GetInstance().CancelAuthentication(testContextId);
    EXPECT_NE(ret, SUCCESS);
}

HWTEST_F(UserAuthClientTest, UserAuthClientBeginIdentification, TestSize.Level0)
{
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    auto testCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().BeginIdentification(testChallenge, testAuthType, testCallback);
}

HWTEST_F(UserAuthClientTest, UserAuthClientCancelIdentification, TestSize.Level0)
{
    uint64_t testContextId = 122;
    int32_t ret = UserAuthClient::GetInstance().CancelIdentification(testContextId);
    EXPECT_NE(ret, SUCCESS);
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetVersion, TestSize.Level0)
{
    int32_t version = UserAuthClientImpl::Instance().GetVersion();
    EXPECT_EQ(version, 0);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS