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

#include "executor_messenger_proxy_test.h"

#include "executor_messenger_proxy.h"
#include "iam_ptr.h"
#include "mock_remote_object.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ExecutorMessengerProxyTest::SetUpTestCase()
{
}

void ExecutorMessengerProxyTest::TearDownTestCase()
{
}

void ExecutorMessengerProxyTest::SetUp()
{
}

void ExecutorMessengerProxyTest::TearDown()
{
}

HWTEST_F(ExecutorMessengerProxyTest, TestSendData_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, ExecutorMessengerInterfaceCode::CO_AUTH_SEND_DATA);
                EXPECT_TRUE(reply.WriteInt32(SUCCESS));
                return OHOS::NO_ERROR;
            }
        );
    
    uint64_t scheduleId = 6598;
    ExecutorRole dstRole = COLLECTOR;
    std::vector<uint8_t> message = {1, 2, 4, 6};
    
    auto proxy = Common::MakeShared<ExecutorMessengerProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    EXPECT_EQ(proxy->SendData(scheduleId, dstRole, message), SUCCESS);
}

HWTEST_F(ExecutorMessengerProxyTest, TestFinish_001, TestSize.Level0)
{
    uint64_t scheduleId = 6598;
    ResultCode resultCode = SUCCESS;
    std::shared_ptr<Attributes> finalResult = nullptr;

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<ExecutorMessengerProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    EXPECT_EQ(proxy->Finish(scheduleId, resultCode, finalResult), INVALID_PARAMETERS);
}

HWTEST_F(ExecutorMessengerProxyTest, TestFinish_002, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, ExecutorMessengerInterfaceCode::CO_AUTH_FINISH);
                EXPECT_TRUE(reply.WriteInt32(SUCCESS));
                return OHOS::NO_ERROR;
            }
        );

    uint64_t scheduleId = 6598;
    ResultCode resultCode = SUCCESS;
    std::shared_ptr<Attributes> finalResult = Common::MakeShared<Attributes>();
    EXPECT_NE(finalResult, nullptr);

    auto proxy = Common::MakeShared<ExecutorMessengerProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    EXPECT_EQ(proxy->Finish(scheduleId, resultCode, finalResult), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
