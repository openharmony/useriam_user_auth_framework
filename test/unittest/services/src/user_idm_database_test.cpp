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
#include "user_idm_database_test.h"

#include "mock_iuser_auth_interface.h"
#include "user_idm_database_impl.h"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

using HdiCredentialInfo = OHOS::HDI::UserAuth::V1_0::CredentialInfo;
using HDIEnrolledInfo = OHOS::HDI::UserAuth::V1_0::EnrolledInfo;
using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;

void UserIdmDatabaseTest::SetUpTestCase()
{
}

void UserIdmDatabaseTest::TearDownTestCase()
{
}

void UserIdmDatabaseTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void UserIdmDatabaseTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserIdmDatabaseTest, FailedGetSecUserInfo, TestSize.Level1)
{
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, GetUserInfo(_, _, _, _)).WillRepeatedly(Return(1));
    auto &database = UserIdmDatabase::Instance();
    constexpr int32_t USER_ID = 100;
    auto secUserInfo = database.GetSecUserInfo(USER_ID);
    EXPECT_EQ(secUserInfo, nullptr);
}

HWTEST_F(UserIdmDatabaseTest, FailedGetSecUserInfoNoPin, TestSize.Level1)
{
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    constexpr int32_t USER_ID = 100;
    constexpr uint64_t SECURE_UID = 200;
    auto fillUpInfos = [](std::vector<HDIEnrolledInfo> &list) {
        std::vector<HDIEnrolledInfo> infos = {};
        HDIEnrolledInfo info1 = {
            .enrolledId = 0,
            .authType = static_cast<HdiAuthType>(2),
        };
        infos.emplace_back((info1));
        list.swap(infos);
    };

    EXPECT_CALL(*mock, GetUserInfo(USER_ID, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(SECURE_UID), WithArg<3>(fillUpInfos), Return(0)));

    auto &database = UserIdmDatabase::Instance();
    auto secUserInfo = database.GetSecUserInfo(USER_ID);

    EXPECT_NE(secUserInfo, nullptr);
}

HWTEST_F(UserIdmDatabaseTest, FailedGetSecUserInfoNoEnrolledInfo, TestSize.Level1)
{
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    constexpr int32_t USER_ID = 100;
    constexpr uint64_t SECURE_UID = 200;
    auto fillUpInfos = [](std::vector<HDIEnrolledInfo> &list) {
        std::vector<HDIEnrolledInfo> infos = {};
        list.swap(infos);
    };

    EXPECT_CALL(*mock, GetUserInfo(USER_ID, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(SECURE_UID), WithArg<3>(fillUpInfos), Return(0)));

    auto secUserInfo = UserIdmDatabase::Instance().GetSecUserInfo(USER_ID);

    // test EnrolledInfo is null
    EXPECT_EQ(secUserInfo, nullptr);
}

HWTEST_F(UserIdmDatabaseTest, SuccessfulGetSecUserInfo, TestSize.Level1)
{
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    constexpr int32_t USER_ID = 100;
    constexpr uint64_t SECURE_UID = 200;
    constexpr PinSubType PIN_SUB_TYPE = PIN_NUMBER;
    auto fillUpInfos = [](std::vector<HDIEnrolledInfo> &list) {
        std::vector<HDIEnrolledInfo> infos = {};
        HDIEnrolledInfo info1 = {
            .enrolledId = 0,
            .authType = static_cast<HdiAuthType>(1),
        };
        infos.emplace_back((info1));
        HDIEnrolledInfo info2 = {
            .enrolledId = 1,
            .authType = static_cast<HdiAuthType>(2),
        };
        infos.emplace_back((info2));
        list.swap(infos);
    };

    using HdiPinSubType = OHOS::HDI::UserAuth::V1_0::PinSubType;
    EXPECT_CALL(*mock, GetUserInfo(USER_ID, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(SECURE_UID), SetArgReferee<2>(static_cast<HdiPinSubType>(PIN_SUB_TYPE)),
            WithArg<3>(fillUpInfos), Return(0)));

    auto &database = UserIdmDatabase::Instance();
    auto secUserInfo = database.GetSecUserInfo(USER_ID);
    EXPECT_NE(secUserInfo, nullptr);
    EXPECT_EQ(USER_ID, secUserInfo->GetUserId());
    EXPECT_EQ(SECURE_UID, secUserInfo->GetSecUserId());
    EXPECT_EQ(PIN_SUB_TYPE, secUserInfo->GetPinSubType());
    EXPECT_EQ(2U, secUserInfo->GetEnrolledInfo().size());
}

HWTEST_F(UserIdmDatabaseTest, FailedGetCredentialInfoVector, TestSize.Level1)
{
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    // mock hdi interface return 1
    constexpr int32_t USER_ID = 100;
    AuthType authType = PIN;
    EXPECT_CALL(*mock, GetCredential(_, _, _)).WillRepeatedly(Return(1));
    auto &database = UserIdmDatabase::Instance();
    std::vector<std::shared_ptr<CredentialInfo>> info = {};
    auto infoRet = database.GetCredentialInfo(USER_ID, authType);
    EXPECT_EQ(infoRet.size(), 0U);
}

HWTEST_F(UserIdmDatabaseTest, SuccessfulGetCredentialInfoVector, TestSize.Level1)
{
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    constexpr int32_t USER_ID = 100;
    HdiAuthType authType = HdiAuthType::PIN;
    // mock hdi interface return 0
    auto fillUpInfos = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo temp1 = {
            .credentialId = 1,
            .executorIndex = 2,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(1),
            .executorMatcher = 2,
            .executorSensorHint = 3,
        };
        infos.push_back(temp1);
        HdiCredentialInfo temp2 = {
            .credentialId = 2,
            .executorIndex = 3,
            .templateId = 4,
            .authType = static_cast<HdiAuthType>(1),
            .executorMatcher = 3,
            .executorSensorHint = 2,
        };
        infos.push_back(temp2);
        list.swap(infos);
    };
    EXPECT_CALL(*mock, GetCredential(USER_ID, authType, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    auto &database = UserIdmDatabase::Instance();
    AuthType authType1 = PIN;
    auto info = database.GetCredentialInfo(USER_ID, authType1);

    // test return result
    EXPECT_EQ(info.size(), 2U);

    // test temp1
    EXPECT_EQ(USER_ID, info[0]->GetUserId());
    EXPECT_EQ(1U, info[0]->GetCredentialId());
    EXPECT_EQ(2U, info[0]->GetExecutorIndex());
    EXPECT_EQ(3U, info[0]->GetTemplateId());
    EXPECT_EQ(static_cast<AuthType>(1), info[0]->GetAuthType());
    EXPECT_EQ(3U, info[0]->GetExecutorSensorHint());
    EXPECT_EQ(2U, info[0]->GetExecutorMatcher());

    // test temp2
    EXPECT_EQ(USER_ID, info[1]->GetUserId());
    EXPECT_EQ(2U, info[1]->GetCredentialId());
    EXPECT_EQ(3U, info[1]->GetExecutorIndex());
    EXPECT_EQ(4U, info[1]->GetTemplateId());
    EXPECT_EQ(static_cast<AuthType>(1), info[1]->GetAuthType());
    EXPECT_EQ(2U, info[1]->GetExecutorSensorHint());
    EXPECT_EQ(3U, info[1]->GetExecutorMatcher());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS