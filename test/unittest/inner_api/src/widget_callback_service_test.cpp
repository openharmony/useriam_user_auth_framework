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

#include "widget_callback_service_test.h"

#include "iam_ptr.h"
#include "widget_callback_service.h"
#include "mock_iuser_auth_widget_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void WidgetCallbackServiceTest::SetUpTestCase()
{
}

void WidgetCallbackServiceTest::TearDownTestCase()
{
}

void WidgetCallbackServiceTest::SetUp()
{
}

void WidgetCallbackServiceTest::TearDown()
{
}

HWTEST_F(WidgetCallbackServiceTest, WidgetCallbackServiceSendCommand001, TestSize.Level0)
{
    std::shared_ptr<IUserAuthWidgetCallback> impl = nullptr;
    auto service = Common::MakeShared<WidgetCallbackService>(impl);

    std::string cmdData = "cmd";
    service->SendCommand(cmdData);
    EXPECT_NE(service, nullptr);
}

HWTEST_F(WidgetCallbackServiceTest, WidgetCallbackServiceSendCommand002, TestSize.Level0)
{
    std::string testData = "cmd";
    auto widgetCallback = Common::MakeShared<MockIUserAuthWidgetCallback>();
    EXPECT_NE(widgetCallback, nullptr);
    EXPECT_CALL(*widgetCallback, SendCommand(_)).Times(1);
    ON_CALL(*widgetCallback, SendCommand)
        .WillByDefault(
            [&testData](const std::string &cmdData) {
                EXPECT_EQ(cmdData, testData);
            }
        );

    auto service = Common::MakeShared<WidgetCallbackService>(widgetCallback);
    EXPECT_NE(service, nullptr);
    service->SendCommand(testData);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS