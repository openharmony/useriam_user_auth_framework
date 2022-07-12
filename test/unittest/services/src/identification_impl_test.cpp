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
#include <memory>

#include "identification_impl.h"
#include "mock_iuser_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
class IdentificationImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void IdentificationImplTest::SetUpTestCase()
{
}

void IdentificationImplTest::TearDownTestCase()
{
}

void IdentificationImplTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void IdentificationImplTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(IdentificationImplTest, IdentificationHdiError, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginIdentification(contextId, _, _, _, _)).WillRepeatedly(Return(1));

    auto identification = std::make_shared<IdentificationImpl>(contextId, FACE);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(identification->Start(scheduleList, nullptr));
}

HWTEST_F(IdentificationImplTest, IdentificationHdiEmpty, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginIdentification(contextId, _, _, _, _)).WillRepeatedly(Return(0));

    auto enrollment = std::make_shared<IdentificationImpl>(contextId, FACE);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(enrollment->Start(scheduleList, nullptr));
}

HWTEST_F(IdentificationImplTest, IdentificationUpdateHdiError, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    using HdiIdentifyResultInfo = OHOS::HDI::UserAuth::V1_0::IdentifyResultInfo;
    HdiIdentifyResultInfo info;
    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateIdentificationResult(contextId, _, _)).WillRepeatedly(Return(1));
    auto identification = std::make_shared<IdentificationImpl>(contextId, FACE);
    Identification::IdentifyResultInfo retInfo = {};
    EXPECT_FALSE(identification->Update(scheduleResult, retInfo));
}

HWTEST_F(IdentificationImplTest, IdentificationUpdateHdiSuccessful, TestSize.Level0)
{
    constexpr uint64_t contextId = 0x1234567;
    using HdiIdentifyResultInfo = OHOS::HDI::UserAuth::V1_0::IdentifyResultInfo;
    auto fillUpInfos = [](HdiIdentifyResultInfo &infoRet) {
        constexpr int32_t userId = 0x11;
        const std::vector<uint8_t> token = {1, 2, 3, 4, 5, 6};
        HdiIdentifyResultInfo info = {
            .result = 0,
            .userId = userId,
            .token = token,
        };
        infoRet = info;
    };
    std::vector<uint8_t> scheduleResult = {1, 2, 3};
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, UpdateIdentificationResult(contextId, _, _))
        .WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    auto identification = std::make_shared<IdentificationImpl>(contextId, FACE);
    Identification::IdentifyResultInfo retInfo = {};
    EXPECT_TRUE(identification->Update(scheduleResult, retInfo));

    // test IdentifyResultInfo
    EXPECT_EQ(retInfo.result, 0);
    EXPECT_EQ(retInfo.userId, 0x11);
    EXPECT_THAT(retInfo.token, ElementsAre(1, 2, 3, 4, 5, 6));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS