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

#include "user_idm_callback_service_test.h"

#include "user_idm_callback_service.h"
#include "iam_ptr.h"
#include "mock_credential_info.h"
#include "mock_secure_user_info.h"
#include "mock_user_idm_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmCallbackServiceTest::SetUpTestCase()
{
}

void UserIdmCallbackServiceTest::TearDownTestCase()
{
}

void UserIdmCallbackServiceTest::SetUp()
{
}

void UserIdmCallbackServiceTest::TearDown()
{
}

HWTEST_F(UserIdmCallbackServiceTest, UserIdmCallbackServiceTest001, TestSize.Level0)
{
    int32_t testResult = FAIL;
    Attributes testExtraInfo;

    int32_t testModule = 52334;
    int32_t testAcquireInfo = 57845;

    std::shared_ptr<UserIdmClientCallback> idmClientCallback = nullptr;
    auto service = Common::MakeShared<IdmCallbackService>(idmClientCallback);
    EXPECT_NE(service, nullptr);
    service->OnResult(testResult, testExtraInfo);
    service->OnAcquireInfo(testModule, testAcquireInfo, testExtraInfo);
}

HWTEST_F(UserIdmCallbackServiceTest, UserIdmCallbackServiceTest002, TestSize.Level0)
{
    int32_t testResult = FAIL;
    Attributes testExtraInfo;

    int32_t testModule = 52334;
    int32_t testAcquireInfo = 57845;

    auto idmClientCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(idmClientCallback, nullptr);
    EXPECT_CALL(*idmClientCallback, OnResult(_, _)).Times(1);
    ON_CALL(*idmClientCallback, OnResult)
        .WillByDefault(
            [&testResult](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, testResult);
            }
        );
    EXPECT_CALL(*idmClientCallback, OnAcquireInfo(_, _, _)).Times(1);
    ON_CALL(*idmClientCallback, OnAcquireInfo)
        .WillByDefault(
            [&testModule, &testAcquireInfo](int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) {
                EXPECT_EQ(module, testModule);
                EXPECT_EQ(acquireInfo, testAcquireInfo);
            }
        );
    auto service = Common::MakeShared<IdmCallbackService>(idmClientCallback);
    EXPECT_NE(service, nullptr);
    service->OnResult(testResult, testExtraInfo);
    service->OnAcquireInfo(testModule, testAcquireInfo, testExtraInfo);
}

HWTEST_F(UserIdmCallbackServiceTest, IdmGetCredInfoCallbackServiceTest001, TestSize.Level0)
{
    std::vector<std::shared_ptr<IdmGetCredInfoCallbackInterface::CredentialInfo>> testInfoList;

    std::shared_ptr<GetCredentialInfoCallback> getCredInfoCallback = nullptr;
    auto service = Common::MakeShared<IdmGetCredInfoCallbackService>(getCredInfoCallback);
    EXPECT_NE(service, nullptr);
    service->OnCredentialInfos(testInfoList, std::nullopt);
}

HWTEST_F(UserIdmCallbackServiceTest, IdmGetCredInfoCallbackServiceTest002, TestSize.Level0)
{
    uint64_t testCredentialId = 265326;
    uint64_t testTemplateId = 62324;
    AuthType testAuthType = PIN;
    PinSubType testSubType = PIN_SIX;

    std::vector<std::shared_ptr<IdmGetCredInfoCallbackInterface::CredentialInfo>> testInfoList;
    testInfoList.push_back(nullptr);
    auto testCredInfo = Common::MakeShared<MockCredentialInfo>();
    EXPECT_NE(testCredInfo, nullptr);
    testInfoList.push_back(testCredInfo);
    EXPECT_CALL(*testCredInfo, GetCredentialId()).Times(1);
    ON_CALL(*testCredInfo, GetCredentialId)
        .WillByDefault(
            [&testCredentialId]() {
                return testCredentialId;
            }
        );
    EXPECT_CALL(*testCredInfo, GetTemplateId()).Times(1);
    ON_CALL(*testCredInfo, GetTemplateId)
        .WillByDefault(
            [&testTemplateId]() {
                return testTemplateId;
            }
        );
    EXPECT_CALL(*testCredInfo, GetAuthType()).Times(1);
    ON_CALL(*testCredInfo, GetAuthType)
        .WillByDefault(
            [&testAuthType]() {
                return testAuthType;
            }
        );

    auto getCredInfoCallback = Common::MakeShared<MockGetCredentialInfoCallback>();
    EXPECT_NE(getCredInfoCallback, nullptr);
    EXPECT_CALL(*getCredInfoCallback, OnCredentialInfo(_)).Times(1);
    ON_CALL(*getCredInfoCallback, OnCredentialInfo)
        .WillByDefault(
            [&testCredentialId, &testTemplateId, &testAuthType, &testSubType](
                const std::vector<CredentialInfo> &infoList) {
                EXPECT_FALSE(infoList.empty());
                EXPECT_EQ(infoList[0].credentialId, testCredentialId);
                EXPECT_EQ(infoList[0].templateId, testTemplateId);
                EXPECT_EQ(infoList[0].authType, testAuthType);
                EXPECT_TRUE(infoList[0].pinType.has_value());
                EXPECT_EQ(infoList[0].pinType.value(), testSubType);
            }
        );
    auto service = Common::MakeShared<IdmGetCredInfoCallbackService>(getCredInfoCallback);
    EXPECT_NE(service, nullptr);
    service->OnCredentialInfos(testInfoList, testSubType);
}

HWTEST_F(UserIdmCallbackServiceTest, IdmGetSecureUserInfoCallbackServiceTest001, TestSize.Level0)
{
    std::shared_ptr<IdmGetSecureUserInfoCallbackInterface::SecureUserInfo> testUserInfo = nullptr;

    std::shared_ptr<GetSecUserInfoCallback> getSecInfoCallback = nullptr;
    auto service = Common::MakeShared<IdmGetSecureUserInfoCallbackService>(getSecInfoCallback);
    EXPECT_NE(service, nullptr);
    service->OnSecureUserInfo(testUserInfo);
}

HWTEST_F(UserIdmCallbackServiceTest, IdmGetSecureUserInfoCallbackServiceTest002, TestSize.Level0)
{
    uint64_t testSecUserId = 54871;
    auto testUserInfo = Common::MakeShared<MockSecureUserInfo>();
    EXPECT_NE(testUserInfo, nullptr);
    EXPECT_CALL(*testUserInfo, GetSecUserId()).Times(1);
    ON_CALL(*testUserInfo, GetSecUserId)
        .WillByDefault(
            [&testSecUserId]() {
                return testSecUserId;
            }
        );

    auto getSecInfoCallback = Common::MakeShared<MockGetSecUserInfoCallback>();
    EXPECT_NE(getSecInfoCallback, nullptr);
    EXPECT_CALL(*getSecInfoCallback, OnSecUserInfo(_)).Times(1);
    ON_CALL(*getSecInfoCallback, OnSecUserInfo)
        .WillByDefault(
            [&testSecUserId](const SecUserInfo &info) {
                EXPECT_EQ(info.secureUid, testSecUserId);
            }
        );

    auto service = Common::MakeShared<IdmGetSecureUserInfoCallbackService>(getSecInfoCallback);
    EXPECT_NE(service, nullptr);
    service->OnSecureUserInfo(testUserInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS