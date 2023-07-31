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

#include "widget_callback_stub_test.h"

#include "iam_ptr.h"
#include "mock_widget_callback_service_test.h"
#include "user_auth_interface_ipc_interface_code.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void WidgetCallbackStubTest::SetUpTestCase()
{
}

void WidgetCallbackStubTest::TearDownTestCase()
{
}

void WidgetCallbackStubTest::SetUp()
{
}

void WidgetCallbackStubTest::TearDown()
{
}

HWTEST_F(WidgetCallbackStubTest, WidgetCallbackStubOnRemoteRequest001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = UserAuthInterfaceCode::USER_AUTH_ON_SEND_COMMAND;
    EXPECT_TRUE(data.WriteInterfaceToken(WidgetCallbackInterface::GetDescriptor()));
    auto service = Common::MakeShared<MockWidgetCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, SendCommand(_)).Times(1);
    EXPECT_EQ(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}

HWTEST_F(WidgetCallbackStubTest, WidgetCallbackStubOnRemoteRequest002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    uint32_t code = 0;
    EXPECT_TRUE(data.WriteInterfaceToken(WidgetCallbackInterface::GetDescriptor()));
    auto service = Common::MakeShared<MockWidgetCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_NE(service->OnRemoteRequest(code, data, reply, option), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS