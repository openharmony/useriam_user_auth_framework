/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "widget_schedule_node_impl.h"

#include <future>

#include "mock_authentication.h"
#include "mock_context.h"
#include "mock_resource_node.h"
#include "mock_schedule_node.h"
#include "schedule_node_impl.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetScheduleNodeImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void WidgetScheduleNodeImplTest::SetUpTestCase()
{
}

void WidgetScheduleNodeImplTest::TearDownTestCase()
{
}

void WidgetScheduleNodeImplTest::SetUp()
{
    static int32_t testNo = 0;
    PRINT_HILOGE("WidgetScheduleNodeImplTest_%{public}d", ++testNo);
}

void WidgetScheduleNodeImplTest::TearDown()
{
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplTest_0001, TestSize.Level0)
{
    auto schedule = Common::MakeShared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    EXPECT_TRUE(schedule->StartSchedule());
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplTest_0002, TestSize.Level0)
{
    auto schedule = Common::MakeShared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    EXPECT_TRUE(schedule->StopSchedule());
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplTest_0004, TestSize.Level0)
{
    auto schedule = Common::MakeShared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);

    std::vector<AuthType> authTypeList;
    authTypeList.push_back(ALL);
    authTypeList.push_back(PIN);
    authTypeList.push_back(FACE);
    authTypeList.push_back(FINGERPRINT);
    EXPECT_TRUE(schedule->StartAuthList(authTypeList));
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplTest_0005, TestSize.Level0)
{
    auto schedule = Common::MakeShared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);

    std::vector<AuthType> authTypeList;
    authTypeList.push_back(ALL);
    authTypeList.push_back(PIN);
    authTypeList.push_back(FACE);
    authTypeList.push_back(FINGERPRINT);
    EXPECT_TRUE(schedule->StopAuthList(authTypeList));
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplTest_0006, TestSize.Level0)
{
    auto schedule = Common::MakeShared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);

    AuthType authType = PIN;
    EXPECT_TRUE(schedule->SuccessAuth(authType));
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplTest_0007, TestSize.Level0)
{
    auto schedule = Common::MakeShared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);

    AuthType authType = PIN;
    EXPECT_TRUE(schedule->NaviPinAuth());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
