/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "widget_context.h"

#include <future>

#include "mock_widget_schedule_node_callback.h"
#include "iam_logger.h"
#include "iam_ptr.h"

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
}

void WidgetScheduleNodeImplTest::TearDown()
{
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartSchedule, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::shared_ptr<MockWidgetScheduleNodeCallback> widgetContext =
        Common::MakeShared<MockWidgetScheduleNodeCallback>();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(widgetContext);
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(false));
    EXPECT_CALL(*widgetContext, EndAuthAsCancel()).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->StartSchedule());
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStopSchedule, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::shared_ptr<MockWidgetScheduleNodeCallback> widgetContext =
        Common::MakeShared<MockWidgetScheduleNodeCallback>();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(widgetContext);
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, EndAuthAsCancel()).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->StopSchedule());
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartAuthList, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    std::shared_ptr<MockWidgetScheduleNodeCallback> widgetContext =
        Common::MakeShared<MockWidgetScheduleNodeCallback>();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(widgetContext);
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, ExecuteAuthList(_)).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->StartAuthList(authTypeList));
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStopAuthList, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    std::shared_ptr<MockWidgetScheduleNodeCallback> widgetContext =
        Common::MakeShared<MockWidgetScheduleNodeCallback>();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(widgetContext);
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, ExecuteAuthList(_)).WillRepeatedly(Return());
    schedule->StartAuthList(authTypeList);
    EXPECT_CALL(*widgetContext, StopAuthList(_)).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->StopAuthList(authTypeList));
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplSuccessAuth, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    std::shared_ptr<MockWidgetScheduleNodeCallback> widgetContext =
        Common::MakeShared<MockWidgetScheduleNodeCallback>();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(widgetContext);
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, ExecuteAuthList(_)).WillRepeatedly(Return());
    schedule->StartAuthList(authTypeList);
    EXPECT_CALL(*widgetContext, SuccessAuth(_)).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->SuccessAuth(AuthType::PIN));
    ON_CALL(*widgetContext, LaunchWidget()).WillByDefault(Return(true));
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplNaviPinAuth, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::shared_ptr<MockWidgetScheduleNodeCallback> widgetContext =
        Common::MakeShared<MockWidgetScheduleNodeCallback>();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(widgetContext);
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, EndAuthAsNaviPin()).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->NaviPinAuth());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
