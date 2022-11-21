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

#include "co_auth_stub_test.h"

#include "mock_executor_callback.h"
#include "mock_co_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void CoAuthStubTest::SetUpTestCase()
{
}

void CoAuthStubTest::TearDownTestCase()
{
}

void CoAuthStubTest::SetUp()
{
}

void CoAuthStubTest::TearDown()
{
}

HWTEST_F(CoAuthStubTest, CoAuthStubTestExecutorRegister001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    CoAuthInterface::ExecutorRegisterInfo testInfo = {};
    testInfo.authType = PIN;
    testInfo.executorRole = SCHEDULER;
    testInfo.executorSensorHint = 0;
    testInfo.executorMatcher = 0;
    testInfo.esl = ESL1;
    testInfo.publicKey = {'a', 'b', 'c', 'd'};

    uint64_t testContextId = 124545;

    sptr<MockExecutorCallback> callback = new MockExecutorCallback();
    EXPECT_NE(callback, nullptr);
    MockCoAuthService service;
    EXPECT_CALL(service, ExecutorRegister(_, _)).Times(1);
    ON_CALL(service, ExecutorRegister)
        .WillByDefault(
            [&testInfo, &testContextId](const CoAuthInterface::ExecutorRegisterInfo &info,
                sptr<ExecutorCallbackInterface> &callback) {
                EXPECT_EQ(info.authType, testInfo.authType);
                EXPECT_EQ(info.executorRole, testInfo.executorRole);
                EXPECT_EQ(info.executorSensorHint, testInfo.executorSensorHint);
                EXPECT_EQ(info.executorMatcher, testInfo.executorMatcher);
                EXPECT_EQ(info.esl, testInfo.esl);
                EXPECT_THAT(info.publicKey, ElementsAreArray(testInfo.publicKey));
                return testContextId;
            }
        );

    EXPECT_TRUE(data.WriteInterfaceToken(CoAuthInterface::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(testInfo.authType));
    EXPECT_TRUE(data.WriteInt32(testInfo.executorRole));
    EXPECT_TRUE(data.WriteUint32(testInfo.executorSensorHint));
    EXPECT_TRUE(data.WriteUint32(testInfo.executorMatcher));
    EXPECT_TRUE(data.WriteInt32(testInfo.esl));
    EXPECT_TRUE(data.WriteUInt8Vector(testInfo.publicKey));
    EXPECT_NE(callback->AsObject(), nullptr);
    EXPECT_TRUE(data.WriteRemoteObject(callback->AsObject()));
    uint32_t code = CoAuthInterface::CO_AUTH_EXECUTOR_REGISTER;
    MessageOption option(MessageOption::TF_SYNC);

    EXPECT_EQ(SUCCESS, service.OnRemoteRequest(code, data, reply, option));
    uint64_t contextId = -1;
    EXPECT_TRUE(reply.ReadUint64(contextId));
    EXPECT_EQ(contextId, testContextId);
}

HWTEST_F(CoAuthStubTest, CoAuthStubTestExecutorRegister002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    uint32_t code = CoAuthInterface::CO_AUTH_EXECUTOR_REGISTER;
    MessageOption option(MessageOption::TF_SYNC);

    MockCoAuthService service;
    EXPECT_EQ(GENERAL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(CoAuthStubTest, CoAuthStubTestExecutorRegister003, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    EXPECT_TRUE(data.WriteInterfaceToken(CoAuthInterface::GetDescriptor()));
    uint32_t code = CoAuthInterface::CO_AUTH_EXECUTOR_REGISTER;
    MessageOption option(MessageOption::TF_SYNC);

    MockCoAuthService service;
    EXPECT_EQ(READ_PARCEL_ERROR, service.OnRemoteRequest(code, data, reply, option));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS