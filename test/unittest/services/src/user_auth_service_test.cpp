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

#include "user_auth_service_test.h"

#include "iam_common_defines.h"
#include "mock_iuser_auth_interface.h"
#include "mock_user_auth_callback.h"
#include "user_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthServiceTest::SetUpTestCase()
{
}

void UserAuthServiceTest::TearDownTestCase()
{
}

void UserAuthServiceTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void UserAuthServiceTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus, TestSize.Level0)
{
    UserAuthService service(100, true);
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL3;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAuthTrustLevel(_, _, _)).Times(1);
    EXPECT_NE(SUCCESS, service.GetAvailableStatus(testAuthType, testAuthTrustLevel));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 123;
    AuthType testAuthType = FACE;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE};
    sptr<GetExecutorPropertyCallbackInterface> testCallback = new MockGetExecutorPropertyCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockGetExecutorPropertyCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnGetExecutorPropertyResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).Times(1);
    service.GetProperty(testUserId, testAuthType, testKeys, testCallback);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetProperty, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 124;
    AuthType testAuthType = FACE;
    Attributes testAttr;
    sptr<SetExecutorPropertyCallbackInterface> testCallback = new MockSetExecutorPropertyCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockSetExecutorPropertyCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnSetExecutorPropertyResult(_)).Times(1);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).Times(1);
    service.SetProperty(testUserId, testAuthType, testAttr, testCallback);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser001, TestSize.Level0)
{
    UserAuthService service(100, true);
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(1);
    uint64_t contextId = service.AuthUser(std::nullopt, testChallenge, testAuthType, testAuthTrustLevel, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 125;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(1);
    uint64_t contextId = service.AuthUser(testUserId, testChallenge, testAuthType, testAuthTrustLevel, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify, TestSize.Level0)
{
    UserAuthService service(100, true);
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginIdentification(_, _, _, _, _)).Times(1);
    uint64_t contextId = service.Identify(testChallenge, testAuthType, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCancelAuthOrIdentify, TestSize.Level0)
{
    UserAuthService service(100, true);
    uint64_t testContextId = 12355236;
    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId), GENERAL_ERROR);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetVersion, TestSize.Level0)
{
    UserAuthService service(100, true);
    EXPECT_EQ(service.GetVersion(), 0);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS