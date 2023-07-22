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
#include "widget_context.h"

#include <future>

#include "mock_widget_schedule_node_callback.h"
#include "iam_logger.h"

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

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartSchedule001, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    auto widgetContext = new MockWidgetScheduleNodeCallback();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(std::shared_ptr<WidgetScheduleNodeCallback>(widgetContext));
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    EXPECT_TRUE(schedule->StartSchedule());
    testing::Mock::AllowLeak(widgetContext);
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartSchedule002, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    auto widgetContext = new MockWidgetScheduleNodeCallback();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(std::shared_ptr<WidgetScheduleNodeCallback>(widgetContext));
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(false));
    EXPECT_CALL(*widgetContext, EndAuthAsCancel()).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->StartSchedule());
    testing::Mock::AllowLeak(widgetContext);
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStopSchedule, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    auto widgetContext = new MockWidgetScheduleNodeCallback();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(std::shared_ptr<WidgetScheduleNodeCallback>(widgetContext));
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, EndAuthAsCancel()).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->StopSchedule());
    testing::Mock::AllowLeak(widgetContext);
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStartAuthList, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    auto widgetContext = new MockWidgetScheduleNodeCallback();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(std::shared_ptr<WidgetScheduleNodeCallback>(widgetContext));
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, ExecuteAuthList(_)).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->StartAuthList(authTypeList));
    testing::Mock::AllowLeak(widgetContext);
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplStopAuthList, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    auto widgetContext = new MockWidgetScheduleNodeCallback();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(std::shared_ptr<WidgetScheduleNodeCallback>(widgetContext));
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, ExecuteAuthList(_)).WillRepeatedly(Return());
    schedule->StartAuthList(authTypeList);
    EXPECT_CALL(*widgetContext, StopAuthList(_)).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->StopAuthList(authTypeList));
    testing::Mock::AllowLeak(widgetContext);
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplSuccessAuth, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    std::vector<AuthType> authTypeList = {AuthType::ALL, AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    auto widgetContext = new MockWidgetScheduleNodeCallback();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(std::shared_ptr<WidgetScheduleNodeCallback>(widgetContext));
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, ExecuteAuthList(_)).WillRepeatedly(Return());
    schedule->StartAuthList(authTypeList);
    EXPECT_CALL(*widgetContext, SuccessAuth(_)).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->SuccessAuth(AuthType::PIN));
    testing::Mock::AllowLeak(widgetContext);
}

HWTEST_F(WidgetScheduleNodeImplTest, WidgetScheduleNodeImplNaviPinAuth, TestSize.Level0)
{
    auto schedule = std::make_shared<WidgetScheduleNodeImpl>();
    ASSERT_NE(schedule, nullptr);
    auto widgetContext = new MockWidgetScheduleNodeCallback();
    ASSERT_NE(widgetContext, nullptr);
    schedule->SetCallback(std::shared_ptr<WidgetScheduleNodeCallback>(widgetContext));
    EXPECT_CALL(*widgetContext, LaunchWidget()).WillRepeatedly(Return(true));
    schedule->StartSchedule();
    EXPECT_CALL(*widgetContext, EndAuthAsNaviPin()).WillRepeatedly(Return());
    EXPECT_TRUE(schedule->NaviPinAuth());
    testing::Mock::AllowLeak(widgetContext);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
