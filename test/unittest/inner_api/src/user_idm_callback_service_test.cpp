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
    std::vector<CredentialInfo> credInfoList;

    std::shared_ptr<GetCredentialInfoCallback> getCredInfoCallback = nullptr;
    auto service = Common::MakeShared<IdmGetCredInfoCallbackService>(getCredInfoCallback);
    EXPECT_NE(service, nullptr);
    service->OnCredentialInfos(credInfoList);
}

HWTEST_F(UserIdmCallbackServiceTest, IdmGetCredInfoCallbackServiceTest002, TestSize.Level0)
{
    CredentialInfo info1 = {PIN, PIN_SIX, 10, 20};
    CredentialInfo info2 = {FACE, std::nullopt, 100, 200};
    CredentialInfo info3 = {FINGERPRINT, std::nullopt, 1000, 2000};
    std::vector<CredentialInfo> credInfoList = {info1, info2, info3};

    auto getCredInfoCallback = Common::MakeShared<MockGetCredentialInfoCallback>();
    EXPECT_NE(getCredInfoCallback, nullptr);
    EXPECT_CALL(*getCredInfoCallback, OnCredentialInfo(_))
        .WillOnce(
            [](const std::vector<CredentialInfo> &infoList) {
                EXPECT_EQ(infoList.size(), 3);
                EXPECT_EQ(infoList[0].authType, PIN);
                EXPECT_EQ(infoList[1].authType, FACE);
                EXPECT_EQ(infoList[2].authType, FINGERPRINT);
            }
        );

    auto service = Common::MakeShared<IdmGetCredInfoCallbackService>(getCredInfoCallback);
    EXPECT_NE(service, nullptr);
    service->OnCredentialInfos(credInfoList);
}

HWTEST_F(UserIdmCallbackServiceTest, IdmGetSecureUserInfoCallbackServiceTest001, TestSize.Level0)
{
    SecUserInfo secUserInfo = {};

    std::shared_ptr<GetSecUserInfoCallback> getSecInfoCallback = nullptr;
    auto service = Common::MakeShared<IdmGetSecureUserInfoCallbackService>(getSecInfoCallback);
    EXPECT_NE(service, nullptr);
    service->OnSecureUserInfo(secUserInfo);
}

HWTEST_F(UserIdmCallbackServiceTest, IdmGetSecureUserInfoCallbackServiceTest002, TestSize.Level0)
{
    auto getSecInfoCallback = Common::MakeShared<MockGetSecUserInfoCallback>();
    EXPECT_NE(getSecInfoCallback, nullptr);
    EXPECT_CALL(*getSecInfoCallback, OnSecUserInfo(_))
        .WillOnce(
            [](const SecUserInfo &info) {
                EXPECT_EQ(info.secureUid, 1000);
                EXPECT_EQ(info.enrolledInfo.size(), 2);
                EXPECT_EQ(info.enrolledInfo[0].authType, FACE);
                EXPECT_EQ(info.enrolledInfo[0].enrolledId, 10);
                EXPECT_EQ(info.enrolledInfo[1].authType, FINGERPRINT);
                EXPECT_EQ(info.enrolledInfo[1].enrolledId, 20);
            }
        );

    auto service = Common::MakeShared<IdmGetSecureUserInfoCallbackService>(getSecInfoCallback);
    EXPECT_NE(service, nullptr);

    SecUserInfo secUserInfo = {};
    secUserInfo.secureUid = 1000;
    secUserInfo.enrolledInfo = {{FACE, 10}, {FINGERPRINT, 20}};
    service->OnSecureUserInfo(secUserInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS