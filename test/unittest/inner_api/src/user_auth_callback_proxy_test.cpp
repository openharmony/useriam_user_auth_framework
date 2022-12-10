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

#include "user_auth_callback_proxy_test.h"

#include "iam_ptr.h"
#include "mock_remote_object.h"
#include "user_auth_callback_proxy.h"
#include "user_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthCallbackProxyTest::SetUpTestCase()
{
}

void UserAuthCallbackProxyTest::TearDownTestCase()
{
}

void UserAuthCallbackProxyTest::SetUp()
{
}

void UserAuthCallbackProxyTest::TearDown()
{
}

HWTEST_F(UserAuthCallbackProxyTest, TestOnResult_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, UserAuthInterface::USER_AUTH_ON_RESULT);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<UserAuthCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    int32_t result = 0;
    Attributes extraInfo;
    proxy->OnResult(result, extraInfo);
}

HWTEST_F(UserAuthCallbackProxyTest, TestOnAcquireInfo_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, UserAuthInterface::USER_AUTH_ACQUIRE_INFO);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<UserAuthCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    int32_t module = 12;
    int32_t acquireInfo = 20;
    Attributes extraInfo;
    proxy->OnAcquireInfo(module, acquireInfo, extraInfo);
}

HWTEST_F(UserAuthCallbackProxyTest, TestOnGetExecutorPropertyResult_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, UserAuthInterface::USER_AUTH_GET_EX_PROP);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<GetExecutorPropertyCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    int32_t result = 0;
    Attributes attributes;
    proxy->OnGetExecutorPropertyResult(result, attributes);
}

HWTEST_F(UserAuthCallbackProxyTest, TestOnSetExecutorPropertyResult_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, UserAuthInterface::USER_AUTH_SET_EX_PROP);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<SetExecutorPropertyCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    int32_t result = 0;
    proxy->OnSetExecutorPropertyResult(result);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
