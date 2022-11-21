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

#include "iam_ptr.h"

#include "credential_info_impl.h"
#include "enrollment_impl.h"
#include "resource_node_pool.h"
#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "mock_schedule_node_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;
using HdiEnrollParam = OHOS::HDI::UserAuth::V1_0::EnrollParam;
using HdiExecutorInfo = OHOS::HDI::UserAuth::V1_0::ExecutorInfo;
using HdiScheduleInfo = OHOS::HDI::UserAuth::V1_0::ScheduleInfo;
using HdiExecutorRole = OHOS::HDI::UserAuth::V1_0::ExecutorRole;
using HdiScheduleMode = OHOS::HDI::UserAuth::V1_0::ScheduleMode;
using HdiExecutorSecureLevel = OHOS::HDI::UserAuth::V1_0::ExecutorSecureLevel;
class EnrollmentImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void EnrollmentImplTest::SetUpTestCase()
{
}

void EnrollmentImplTest::TearDownTestCase()
{
}

void EnrollmentImplTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void EnrollmentImplTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(EnrollmentImplTest, EnrollmentHdiError, TestSize.Level0)
{
    constexpr int32_t userId = 0x11;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginEnrollment(userId, _, _, _)).WillRepeatedly(Return(1));

    auto enrollment = std::make_shared<EnrollmentImpl>(userId, FACE);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(enrollment->Start(scheduleList, nullptr));
}

HWTEST_F(EnrollmentImplTest, EnrollmentHdiEmpty, TestSize.Level0)
{
    constexpr int32_t userId = 0x11;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginEnrollment(userId, _, _, _)).WillRepeatedly(Return(0));

    auto enroll = std::make_shared<EnrollmentImpl>(userId, FACE);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(enroll->Start(scheduleList, nullptr));
}

/**
 * @tc.name: enroll_update
 * @tc.desc: verify hdi enroll
 * @tc.type: FUNC
 * @tc.require: issueI5NXMW
 */
HWTEST_F(EnrollmentImplTest, EnrollmentUpdateHdiError, TestSize.Level0)
{
    constexpr int32_t userId = 0x11;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateEnrollmentResult(userId, _, _)).WillRepeatedly(Return(1));

    auto enroll = std::make_shared<EnrollmentImpl>(userId, FACE);
    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    uint64_t credentialId = 0;
    std::shared_ptr<CredentialInfo> info = nullptr;
    std::vector<uint8_t> rootSecret;
    EXPECT_FALSE(enroll->Update(scheduleResult, credentialId, info, rootSecret));
}

HWTEST_F(EnrollmentImplTest, EnrollmentUpdateHdiSuccessful, TestSize.Level0)
{
    using HdiCredentialInfo = OHOS::HDI::UserAuth::V1_0::CredentialInfo;
    using HdiEnrollResultInfo = OHOS::HDI::UserAuth::V1_0::EnrollResultInfo;
    constexpr int32_t userId = 0x11;
    constexpr uint64_t credentialIdRet = 0x12;
    std::vector<uint8_t> scheduleResult = {1, 2, 3};

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    auto fillUpInfos = [](HdiEnrollResultInfo &infoRet) {
        HdiCredentialInfo oldInfo = {
            .credentialId = 1,
            .executorIndex = 2,
            .templateId = 3,
            .authType = static_cast<OHOS::HDI::UserAuth::V1_0::AuthType>(0),
            .executorMatcher = 5,
            .executorSensorHint = 6,
        };
        HdiEnrollResultInfo info = {
            .credentialId = credentialIdRet,
            .oldInfo = oldInfo,
        };
        infoRet = info;
    };
    EXPECT_CALL(*mock, UpdateEnrollmentResult(userId, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));

    auto enroll = std::make_shared<EnrollmentImpl>(userId, FACE);
    HdiCredentialInfo oldInfo = {};
    std::shared_ptr<CredentialInfo> info = std::make_shared<CredentialInfoImpl>(userId, oldInfo);
    uint64_t credentialId = 0;
    std::vector<uint8_t> rootSecret;
    EXPECT_TRUE(enroll->Update(scheduleResult, credentialId, info, rootSecret));

    // test return values
    EXPECT_EQ(credentialId, credentialIdRet);
    EXPECT_EQ(info->GetCredentialId(), 1U);
    EXPECT_EQ(info->GetAuthType(), static_cast<AuthType>(0));
    EXPECT_EQ(info->GetExecutorIndex(), 2U);
    EXPECT_EQ(info->GetUserId(), 0x11);
    EXPECT_EQ(info->GetTemplateId(), 3U);
    EXPECT_EQ(info->GetExecutorMatcher(), 5U);
    EXPECT_EQ(info->GetExecutorSensorHint(), 6U);
}

HWTEST_F(EnrollmentImplTest, EnrollmentImplTestStart, TestSize.Level0)
{
    constexpr uint64_t userId = 34567;
    constexpr uint64_t executorIndex = 60;
    
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CancelEnrollment(_))
        .Times(2)
        .WillOnce(Return(HDF_SUCCESS))
        .WillOnce(Return(HDF_FAILURE));
    EXPECT_CALL(*mockHdi, BeginEnrollment(_, _, _, _))
        .WillRepeatedly(
            [](int32_t userId, const std::vector<uint8_t> &authToken, const HdiEnrollParam &param,
                HdiScheduleInfo &info) {
                info.authType = HdiAuthType::FACE;
                info.executorMatcher = 10;
                HdiExecutorInfo executorInfo = {};
                executorInfo.executorIndex = 60;
                executorInfo.info.authType = HdiAuthType::FACE;
                executorInfo.info.esl = HdiExecutorSecureLevel::ESL1;
                executorInfo.info.executorMatcher = 10;
                executorInfo.info.executorRole = HdiExecutorRole::ALL_IN_ONE;
                executorInfo.info.executorSensorHint = 90;
                executorInfo.info.publicKey = {1, 2, 3, 4};
                info.executors.push_back(executorInfo);
                info.scheduleId = 20;
                info.scheduleMode = HdiScheduleMode::IDENTIFY;
                info.templateIds.push_back(30);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, FACE, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    auto enroll = std::make_shared<EnrollmentImpl>(userId, FACE);
    EXPECT_NE(enroll, nullptr);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    auto callback = Common::MakeShared<MockScheduleNodeCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_TRUE(enroll->Start(scheduleList, callback));
    EXPECT_TRUE(enroll->Cancel());

    EXPECT_TRUE(enroll->Start(scheduleList, callback));
    EXPECT_FALSE(enroll->Cancel());

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS