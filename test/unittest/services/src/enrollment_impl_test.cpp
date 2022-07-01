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
#include "credential_info_impl.h"
#include "enrollment_impl.h"
#include "mock_iuser_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;
using EnrollParam = OHOS::HDI::UserAuth::V1_0::EnrollParam;
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

HWTEST_F(EnrollmentImplTest, EnrollmentHdiError, TestSize.Level1)
{
    constexpr int32_t userId = 0x11;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginEnrollment(userId, _, _, _)).WillRepeatedly(Return(1));

    auto enrollment = std::make_shared<EnrollmentImpl>(userId, FACE);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(enrollment->Start(scheduleList, nullptr));
}

HWTEST_F(EnrollmentImplTest, EnrollmentHdiEmpty, TestSize.Level1)
{
    constexpr int32_t userId = 0x11;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginEnrollment(userId, _, _, _)).WillRepeatedly(Return(0));

    auto authentication = std::make_shared<EnrollmentImpl>(userId, FACE);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(authentication->Start(scheduleList, nullptr));
}

HWTEST_F(EnrollmentImplTest, EnrollmentUpdateHdiError, TestSize.Level1)
{
    constexpr int32_t userId = 0x11;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateEnrollmentResult(userId, _, _)).WillRepeatedly(Return(1));

    auto authentication = std::make_shared<EnrollmentImpl>(userId, FACE);
    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    uint64_t credentialId = 0;
    std::shared_ptr<CredentialInfo> info = nullptr;
    EXPECT_FALSE(authentication->Update(scheduleResult, credentialId, info));
}

HWTEST_F(EnrollmentImplTest, EnrollmentUpdateHdiSuccessful, TestSize.Level1)
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
            .oldInfo = oldInfo,
            .credentialId = credentialIdRet,
        };
        infoRet = info;
    };
    EXPECT_CALL(*mock, UpdateEnrollmentResult(userId, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));

    auto authentication = std::make_shared<EnrollmentImpl>(userId, FACE);
    HdiCredentialInfo oldInfo = {};
    std::shared_ptr<CredentialInfo> info = std::make_shared<CredentialInfoImpl>(userId, oldInfo);
    uint64_t credentialId = 0;
    EXPECT_TRUE(authentication->Update(scheduleResult, credentialId, info));

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
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS