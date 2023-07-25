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

#include "widget_callback_proxy_test.h"

#include "iam_ptr.h"
#include "mock_remote_object.h"
#include "widget_callback_proxy.h"
#include "user_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void WidgetCallbackProxyTest::SetUpTestCase()
{
}

void WidgetCallbackProxyTest::TearDownTestCase()
{
}

void WidgetCallbackProxyTest::SetUp()
{
}

void WidgetCallbackProxyTest::TearDown()
{
}

HWTEST_F(WidgetCallbackProxyTest, WidgetCallbackStubOnRemoteRequest001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, UserAuthInterfaceCode::USER_AUTH_ON_SEND_COMMAND);
                return OHOS::NO_ERROR;
            }
        );

    auto proxy = Common::MakeShared<WidgetCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    std::string cmdData = "cmd";
    proxy->SendCommand(cmdData);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS