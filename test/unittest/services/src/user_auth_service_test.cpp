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
#include "mock_resource_node.h"
#include "resource_node_pool.h"
#include "user_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

using HdiCredentialInfo = OHOS::HDI::UserAuth::V1_0::CredentialInfo;
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V1_0::EnrolledInfo;
using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;

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

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus001, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 8;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL3;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAuthTrustLevel(_, _, _)).Times(1);
    EXPECT_NE(SUCCESS, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 8;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = static_cast<AuthTrustLevel>(90000);
    EXPECT_EQ(TRUST_LEVEL_NOT_SUPPORT, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));

    testAuthTrustLevel = ATL2;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAuthTrustLevel(_, _, _)).Times(1);
    ON_CALL(*mockHdi, GetAuthTrustLevel)
        .WillByDefault(
            [](int32_t userId, HdiAuthType authType, uint32_t &authTrustLevel) {
                authTrustLevel = static_cast<AuthTrustLevel>(0);
                return SUCCESS;
            }
        );
    EXPECT_EQ(TRUST_LEVEL_NOT_SUPPORT, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus003, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 8;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAuthTrustLevel(_, _, _)).WillRepeatedly([]() {
        return NOT_ENROLLED;
    });
    EXPECT_EQ(TRUST_LEVEL_NOT_SUPPORT, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));

    testApiVersion = 9;
    EXPECT_EQ(NOT_ENROLLED, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty001, TestSize.Level0)
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

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 123;
    AuthType testAuthType = FACE;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE};
    sptr<GetExecutorPropertyCallbackInterface> testCallback = nullptr;
    service.GetProperty(testUserId, testAuthType, testKeys, testCallback);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).Times(1);
    ON_CALL(*mockHdi, GetCredential)
        .WillByDefault(
            [](int32_t userId, HdiAuthType authType, std::vector<HdiCredentialInfo> &infos) {
                HdiCredentialInfo tempInfo = {
                    .credentialId = 1,
                    .executorIndex = 2,
                    .templateId = 3,
                    .authType = static_cast<HdiAuthType>(1),
                    .executorMatcher = 2,
                    .executorSensorHint = 3,
                };
                infos.push_back(tempInfo);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    EXPECT_CALL(*node, GetProperty(_, _)).WillRepeatedly([]() {
        return FAIL;
    });
    testCallback = new MockGetExecutorPropertyCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockGetExecutorPropertyCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnGetExecutorPropertyResult(_, _)).Times(1);
    service.GetProperty(testUserId, testAuthType, testKeys, testCallback);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetProperty001, TestSize.Level0)
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

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetProperty002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 124;
    AuthType testAuthType = FACE;
    Attributes testAttr;
    sptr<SetExecutorPropertyCallbackInterface> testCallback = nullptr;
    service.SetProperty(testUserId, testAuthType, testAttr, testCallback);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).Times(1);
    ON_CALL(*mockHdi, GetCredential)
        .WillByDefault(
            [](int32_t userId, HdiAuthType authType, std::vector<HdiCredentialInfo> &infos) {
                HdiCredentialInfo tempInfo = {
                    .credentialId = 1,
                    .executorIndex = 2,
                    .templateId = 3,
                    .authType = static_cast<HdiAuthType>(1),
                    .executorMatcher = 2,
                    .executorSensorHint = 3,
                };
                infos.push_back(tempInfo);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    EXPECT_CALL(*node, SetProperty(_)).WillRepeatedly([]() {
        return FAIL;
    });
    testCallback = new MockSetExecutorPropertyCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockSetExecutorPropertyCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnSetExecutorPropertyResult(_)).Times(1);
    service.SetProperty(testUserId, testAuthType, testAttr, testCallback);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth001, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 9;
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
    uint64_t contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<UserAuthCallbackInterface> testCallback = nullptr;
    uint64_t contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, testCallback);
    EXPECT_EQ(contextId, 0);

    testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(2);
    testAuthTrustLevel = static_cast<AuthTrustLevel>(90000);
    contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, testCallback);
    EXPECT_EQ(contextId, 0);

    testAuthType = PIN;
    testAuthTrustLevel = ATL1;
    contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser001, TestSize.Level0)
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

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 125;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<UserAuthCallbackInterface> testCallback = nullptr;
    uint64_t contextId = service.AuthUser(testUserId, testChallenge, testAuthType, testAuthTrustLevel, testCallback);
    EXPECT_EQ(contextId, 0);

    testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    testAuthTrustLevel = static_cast<AuthTrustLevel>(90000);
    contextId = service.AuthUser(testUserId, testChallenge, testAuthType, testAuthTrustLevel, testCallback);
    EXPECT_EQ(contextId, 0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify001, TestSize.Level0)
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

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify002, TestSize.Level0)
{
    UserAuthService service(100, true);
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    sptr<UserAuthCallbackInterface> testCallback = nullptr;
    uint64_t contextId = service.Identify(testChallenge, testAuthType, testCallback);
    EXPECT_EQ(contextId, 0);

    testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    testAuthType = PIN;
    contextId = service.Identify(testChallenge, testAuthType, testCallback);
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