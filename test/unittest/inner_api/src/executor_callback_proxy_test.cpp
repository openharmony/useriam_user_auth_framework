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

#include "executor_callback_proxy_test.h"

#include "iam_ptr.h"
#include "executor_callback_proxy.h"
#include "mock_executor_messenger_service.h"
#include "mock_remote_object.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ExecutorCallbackProxyTest::SetUpTestCase()
{
}

void ExecutorCallbackProxyTest::TearDownTestCase()
{
}

void ExecutorCallbackProxyTest::SetUp()
{
}

void ExecutorCallbackProxyTest::TearDown()
{
}

HWTEST_F(ExecutorCallbackProxyTest, TestOnMessengerReady_001, TestSize.Level0)
{
    sptr<ExecutorMessengerInterface> messenger = nullptr;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIdList;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<ExecutorCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    proxy->OnMessengerReady(messenger, publicKey, templateIdList);
}

HWTEST_F(ExecutorCallbackProxyTest, TestOnMessengerReady_002, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, ExecutorCallbackInterface::ON_MESSENGER_READY);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<ExecutorCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    
    sptr<ExecutorMessengerInterface> messenger = new MockExecutorMessengerService();
    EXPECT_NE(messenger, nullptr);
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIdList;
    proxy->OnMessengerReady(messenger, publicKey, templateIdList);
}

HWTEST_F(ExecutorCallbackProxyTest, TestOnBeginExecute_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, ExecutorCallbackInterface::ON_BEGIN_EXECUTE);
                EXPECT_TRUE(reply.WriteInt32(SUCCESS));
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<ExecutorCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    uint64_t scheduleId = 321562;
    std::vector<uint8_t> publicKey;
    Attributes command;

    EXPECT_EQ(proxy->OnBeginExecute(scheduleId, publicKey, command), SUCCESS);
}

HWTEST_F(ExecutorCallbackProxyTest, TestOnEndExecute_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, ExecutorCallbackInterface::ON_END_EXECUTE);
                EXPECT_TRUE(reply.WriteInt32(SUCCESS));
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<ExecutorCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    uint64_t scheduleId = 321562;
    Attributes command;
    EXPECT_EQ(proxy->OnEndExecute(scheduleId, command), SUCCESS);
}

HWTEST_F(ExecutorCallbackProxyTest, TestOnSetProperty_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, ExecutorCallbackInterface::ON_SET_PROPERTY);
                EXPECT_TRUE(reply.WriteInt32(SUCCESS));
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<ExecutorCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    Attributes properties;
    EXPECT_EQ(proxy->OnSetProperty(properties), SUCCESS);
}

HWTEST_F(ExecutorCallbackProxyTest, TestOnGetProperty_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .Times(2)
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, ExecutorCallbackInterface::ON_GET_PROPERTY);
                EXPECT_TRUE(reply.WriteInt32(SUCCESS));
                return OHOS::NO_ERROR;
            }
        )
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, ExecutorCallbackInterface::ON_GET_PROPERTY);
                return GENERAL_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<ExecutorCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    Attributes condition;
    Attributes values;
    EXPECT_EQ(proxy->OnGetProperty(condition, values), SUCCESS);
    EXPECT_EQ(proxy->OnGetProperty(condition, values), GENERAL_ERROR);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
