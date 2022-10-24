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

#include "user_idm_service_test.h"

#include "iam_common_defines.h"
#include "mock_iuser_auth_interface.h"
#include "mock_user_idm_callback.h"
#include "user_idm_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmServiceTest::SetUpTestCase()
{
}

void UserIdmServiceTest::TearDownTestCase()
{
}

void UserIdmServiceTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void UserIdmServiceTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceOpenSession, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    std::vector<uint8_t> challenge;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, OpenSession(_, _)).Times(1);
    int32_t ret = service.OpenSession(testUserId, challenge);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(challenge.size(), 0);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceCloseSession, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 3546;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CloseSession(_)).Times(1);
    service.CloseSession(testUserId);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceGetCredentialInfo, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    AuthType testAuthType = PIN;
    sptr<IdmGetCredInfoCallbackInterface> testCallback = new MockIdmGetCredentialInfoCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmGetCredentialInfoCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnCredentialInfos(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).Times(1);
    int32_t ret = service.GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_NE(ret, SUCCESS);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceGetSecInfo, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    sptr<IdmGetSecureUserInfoCallbackInterface> testCallback = new MockIdmGetSecureUserInfoCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmGetSecureUserInfoCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnSecureUserInfo(_)).Times(1);
    EXPECT_CALL(*mockHdi, GetUserInfo(_, _, _, _)).Times(1);
    int32_t ret = service.GetSecInfo(testUserId, testCallback);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceAddCredential, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15457;
    AuthType testAuthType = PIN;
    PinSubType testPinSubType = PIN_SIX;
    std::vector<uint8_t> testToken = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginEnrollment(_, _, _, _)).Times(1);
    service.AddCredential(testUserId, testAuthType, testPinSubType, testToken, testCallback, false);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceUpdateCredential, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 1548545;
    AuthType testAuthType = FACE;
    PinSubType testPinSubType = PIN_SIX;
    std::vector<uint8_t> testToken = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).Times(1);
    service.UpdateCredential(testUserId, testAuthType, testPinSubType, testToken, testCallback);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceCancel, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 154835;
    int32_t ret = service.Cancel(testUserId);
    EXPECT_NE(ret, SUCCESS);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceEnforceDelUser, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15485;
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetUserInfo(_, _, _, _)).Times(1);
    EXPECT_CALL(*mockHdi, EnforceDeleteUser(_, _)).Times(1);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    int32_t ret = service.EnforceDelUser(testUserId, testCallback);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelUser, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15486465;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, DeleteUser(_, _, _)).Times(1);
    service.DelUser(testUserId, testAuthToken, testCallback);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelCredential, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 1548865;
    uint64_t testCredentialId = 23424;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, DeleteCredential(_, _, _, _)).Times(1);
    service.DelCredential(testUserId, testCredentialId, testAuthToken, testCallback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS