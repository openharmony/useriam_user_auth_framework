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

#include "co_auth_proxy_test.h"

#include "iam_ptr.h"
#include "co_auth_proxy.h"
#include "executor_callback_service.h"
#include "mock_remote_object.h"
#include "mock_co_auth_service.h"
#include "mock_executor_register_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void CoAuthProxyTest::SetUpTestCase()
{
}

void CoAuthProxyTest::TearDownTestCase()
{
}

void CoAuthProxyTest::SetUp()
{
}

void CoAuthProxyTest::TearDown()
{
}

HWTEST_F(CoAuthProxyTest, CoAuthProxyExecutorRegister, TestSize.Level0)
{
    CoAuthInterface::ExecutorRegisterInfo testInfo = {};
    testInfo.authType = PIN;
    testInfo.executorRole = COLLECTOR;
    testInfo.executorSensorHint = 11;
    testInfo.executorMatcher = 22;
    testInfo.esl = ESL1;
    testInfo.publicKey = {1, 2, 3, 4};

    uint64_t testExecutorIndex = 73265;

    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    auto proxy = Common::MakeShared<CoAuthProxy>(obj);
    EXPECT_NE(proxy, nullptr);
    auto executorCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    sptr<ExecutorCallbackInterface> testCallback = new (std::nothrow) ExecutorCallbackService(executorCallback);
    auto service = Common::MakeShared<MockCoAuthService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, ExecutorRegister(_, _))
        .Times(Exactly(1))
        .WillOnce(
            [&testInfo, &testExecutorIndex](const CoAuthInterface::ExecutorRegisterInfo &info,
            sptr<ExecutorCallbackInterface> &callback) {
            EXPECT_EQ(testInfo.authType, info.authType);
            EXPECT_EQ(testInfo.executorRole, info.executorRole);
            EXPECT_EQ(testInfo.executorSensorHint, info.executorSensorHint);
            EXPECT_EQ(testInfo.executorMatcher, info.executorMatcher);
            EXPECT_EQ(testInfo.esl, info.esl);
            EXPECT_THAT(testInfo.publicKey, ElementsAreArray(info.publicKey));
            return testExecutorIndex;
        });
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(1);
    ON_CALL(*obj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return OHOS::NO_ERROR;
        });
    proxy->ExecutorRegister(testInfo, testCallback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS