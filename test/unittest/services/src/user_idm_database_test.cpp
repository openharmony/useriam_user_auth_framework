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

HWTEST_F(UserIdmDatabaseTest, FailedGetSecUserInfo, TestSize.Level0)
{
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, GetUserInfo(_, _, _, _)).WillRepeatedly(Return(1));
    auto &database = UserIdmDatabase::Instance();
    constexpr int32_t USER_ID = 100;
    auto secUserInfo = database.GetSecUserInfo(USER_ID);
    EXPECT_EQ(secUserInfo, nullptr);
}

HWTEST_F(UserIdmDatabaseTest, FailedGetSecUserInfoNoPin, TestSize.Level0)
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

HWTEST_F(UserIdmDatabaseTest, FailedGetSecUserInfoNoEnrolledInfo, TestSize.Level0)
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
    EXPECT_NE(secUserInfo, nullptr);
}

HWTEST_F(UserIdmDatabaseTest, SuccessfulGetSecUserInfo, TestSize.Level0)
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

HWTEST_F(UserIdmDatabaseTest, FailedGetCredentialInfoVector, TestSize.Level0)
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

HWTEST_F(UserIdmDatabaseTest, SuccessfulGetCredentialInfoVector, TestSize.Level0)
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

HWTEST_F(UserIdmDatabaseTest, DeleteCredentialInfo001, TestSize.Level0)
{
    int32_t testUserId = 4501;
    uint64_t testCredentialId = 87841;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::shared_ptr<CredentialInfo> testCredInfo = nullptr;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteCredential(_, _, _, _)).WillRepeatedly(Return(1));
    int32_t result = UserIdmDatabase::Instance().DeleteCredentialInfo(testUserId, testCredentialId,
        testAuthToken, testCredInfo);
    EXPECT_EQ(result, 1);
}

HWTEST_F(UserIdmDatabaseTest, DeleteCredentialInfo002, TestSize.Level0)
{
    int32_t testUserId = 4501;
    uint64_t testCredentialId = 87841;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::shared_ptr<CredentialInfo> testCredInfo = nullptr;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteCredential(_, _, _, _)).Times(1);
    ON_CALL(*mockHdi, DeleteCredential)
        .WillByDefault(
            [](int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, HdiCredentialInfo &info) {
                info.authType = static_cast<HdiAuthType>(1);
                info.credentialId = 10;
                info.executorIndex = 20;
                info.executorMatcher = 30;
                info.executorSensorHint = 40;
                info.templateId = 50;
                return HDF_SUCCESS;
            }
        );
    int32_t result = UserIdmDatabase::Instance().DeleteCredentialInfo(testUserId, testCredentialId,
        testAuthToken, testCredInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_NE(testCredInfo, nullptr);
    EXPECT_EQ(testCredInfo->GetAuthType(), PIN);
    EXPECT_EQ(testCredInfo->GetCredentialId(), 10);
    EXPECT_EQ(testCredInfo->GetExecutorIndex(), 20);
    EXPECT_EQ(testCredInfo->GetExecutorMatcher(), 30);
    EXPECT_EQ(testCredInfo->GetExecutorSensorHint(), 40);
    EXPECT_EQ(testCredInfo->GetTemplateId(), 50);
    EXPECT_EQ(testCredInfo->GetUserId(), testUserId);
}

HWTEST_F(UserIdmDatabaseTest, DeleteUser001, TestSize.Level0)
{
    int32_t testUserId = 4501;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<std::shared_ptr<CredentialInfo>> testCredInfos;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteUser(_, _, _)).WillRepeatedly(Return(1));
    int32_t result = UserIdmDatabase::Instance().DeleteUser(testUserId, testAuthToken, testCredInfos);
    EXPECT_EQ(result, 1);
}

HWTEST_F(UserIdmDatabaseTest, DeleteUser002, TestSize.Level0)
{
    int32_t testUserId = 4501;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    std::vector<std::shared_ptr<CredentialInfo>> testCredInfos;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteUser(_, _, _)).Times(1);
    ON_CALL(*mockHdi, DeleteUser)
        .WillByDefault(
            [](int32_t userId, const std::vector<uint8_t> &authToken, std::vector<HdiCredentialInfo> &deletedInfos) {
                HdiCredentialInfo info = {};
                info.authType = static_cast<HdiAuthType>(1);
                info.credentialId = 10;
                info.executorIndex = 20;
                info.executorMatcher = 30;
                info.executorSensorHint = 40;
                info.templateId = 50;
                deletedInfos.emplace_back(info);
                return HDF_SUCCESS;
            }
        );
    int32_t result = UserIdmDatabase::Instance().DeleteUser(testUserId, testAuthToken, testCredInfos);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(testCredInfos.size(), 1);
    EXPECT_NE(testCredInfos[0], nullptr);
    EXPECT_EQ(testCredInfos[0]->GetAuthType(), PIN);
    EXPECT_EQ(testCredInfos[0]->GetCredentialId(), 10);
    EXPECT_EQ(testCredInfos[0]->GetExecutorIndex(), 20);
    EXPECT_EQ(testCredInfos[0]->GetExecutorMatcher(), 30);
    EXPECT_EQ(testCredInfos[0]->GetExecutorSensorHint(), 40);
    EXPECT_EQ(testCredInfos[0]->GetTemplateId(), 50);
    EXPECT_EQ(testCredInfos[0]->GetUserId(), testUserId);
}

HWTEST_F(UserIdmDatabaseTest, DeleteUserEnforce001, TestSize.Level0)
{
    int32_t testUserId = 4501;
    std::vector<std::shared_ptr<CredentialInfo>> testCredInfos;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, EnforceDeleteUser(_, _)).WillRepeatedly(Return(1));
    int32_t result = UserIdmDatabase::Instance().DeleteUserEnforce(testUserId, testCredInfos);
    EXPECT_EQ(result, 1);
}

HWTEST_F(UserIdmDatabaseTest, DeleteUserEnforce002, TestSize.Level0)
{
    int32_t testUserId = 4501;
    std::vector<std::shared_ptr<CredentialInfo>> testCredInfos;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, EnforceDeleteUser(_, _)).Times(1);
    ON_CALL(*mockHdi, EnforceDeleteUser)
        .WillByDefault(
            [](int32_t userId, std::vector<HdiCredentialInfo> &deletedInfos) {
                HdiCredentialInfo info = {};
                info.authType = static_cast<HdiAuthType>(1);
                info.credentialId = 10;
                info.executorIndex = 20;
                info.executorMatcher = 30;
                info.executorSensorHint = 40;
                info.templateId = 50;
                deletedInfos.emplace_back(info);
                return HDF_SUCCESS;
            }
        );
    int32_t result = UserIdmDatabase::Instance().DeleteUserEnforce(testUserId, testCredInfos);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(testCredInfos.size(), 1);
    EXPECT_NE(testCredInfos[0], nullptr);
    EXPECT_EQ(testCredInfos[0]->GetAuthType(), PIN);
    EXPECT_EQ(testCredInfos[0]->GetCredentialId(), 10);
    EXPECT_EQ(testCredInfos[0]->GetExecutorIndex(), 20);
    EXPECT_EQ(testCredInfos[0]->GetExecutorMatcher(), 30);
    EXPECT_EQ(testCredInfos[0]->GetExecutorSensorHint(), 40);
    EXPECT_EQ(testCredInfos[0]->GetTemplateId(), 50);
    EXPECT_EQ(testCredInfos[0]->GetUserId(), testUserId);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS