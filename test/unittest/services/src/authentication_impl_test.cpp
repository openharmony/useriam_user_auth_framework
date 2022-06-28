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

#include "authentication_impl.h"
#include "mock_iuser_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
class AuthenticationImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void AuthenticationImplTest::SetUpTestCase()
{
}

void AuthenticationImplTest::TearDownTestCase()
{
}

void AuthenticationImplTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void AuthenticationImplTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthenticationImplTest, AuthenticationHdiError, TestSize.Level1)
{
    constexpr uint64_t contextId = 0x1234567;
    constexpr int32_t userId = 0x11;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthentication(contextId, _, _)).WillRepeatedly(Return(1));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(authentication->Start(scheduleList, nullptr));
}

HWTEST_F(AuthenticationImplTest, AuthenticationHdiEmpty, TestSize.Level1)
{
    constexpr uint64_t contextId = 0x1234567;
    constexpr int32_t userId = 0x11;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthentication(contextId, _, _)).WillRepeatedly(Return(0));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(authentication->Start(scheduleList, nullptr));
}

HWTEST_F(AuthenticationImplTest, AuthenticationInvalidExecutor, TestSize.Level1)
{
    using ScheduleInfo = OHOS::HDI::UserAuth::V1_0::ScheduleInfo;
    using ExecutorInfo = OHOS::HDI::UserAuth::V1_0::ExecutorInfo;

    constexpr uint64_t contextId = 0x1234567;
    constexpr int32_t userId = 0x11;
    constexpr int32_t executorInfoIndex = 0x100;
    constexpr int32_t scheduleId = 0x1122;

    auto fillInfoList = [](std::vector<ScheduleInfo> &scheduleInfos) {
        ExecutorInfo executorInfo;
        executorInfo.executorIndex = executorInfoIndex;

        ScheduleInfo scheduleInfo;

        scheduleInfo.scheduleId = scheduleId;
        scheduleInfo.templateIds = {0, 1, 2};
        scheduleInfo.authType = OHOS::HDI::UserAuth::V1_0::FACE;
        scheduleInfo.executorMatcher = 0;
        scheduleInfo.scheduleMode = OHOS::HDI::UserAuth::V1_0::ENROLL;
        scheduleInfo.executors.push_back(executorInfo);

        std::vector<ScheduleInfo> list;
        list.emplace_back(scheduleInfo);

        scheduleInfos.swap(list);
    };

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, BeginAuthentication(contextId, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillInfoList), Return(0)));

    auto authentication = std::make_shared<AuthenticationImpl>(contextId, userId, FACE, ATL3);
    std::vector<std::shared_ptr<ScheduleNode>> scheduleList;
    EXPECT_FALSE(authentication->Start(scheduleList, nullptr));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS