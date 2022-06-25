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

#include "co_auth_service_test.h"

#include "co_auth_service.h"
#include "executor_callback_stub.h"

#include <message_parcel.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void CoAuthServiceTest::SetUpTestCase()
{
}

void CoAuthServiceTest::TearDownTestCase()
{
}

void CoAuthServiceTest::SetUp()
{
}

void CoAuthServiceTest::TearDown()
{
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTestOnRemoteRequest, TestSize.Level1)
{
    sptr<ExecutorCallbackStub> callback = new (std::nothrow) ExecutorCallbackStub();
    EXPECT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    ExecutorRegisterInfo info = {};
    info.authType = PIN;
    info.executorRole = SCHEDULER;
    info.executorSensorHint = 0;
    info.executorMatcher = 0;
    info.esl = ESL1;
    info.publicKey = {'a', 'b', 'c', 'd'};
    EXPECT_EQ(data.WriteUint32(info.authType), true);
    EXPECT_EQ(data.WriteUint32(info.executorRole), true);
    EXPECT_EQ(data.WriteUint32(info.esl), true);
    EXPECT_EQ(data.WriteUInt8Vector(info.publicKey), true);
    EXPECT_EQ(data.WriteRemoteObject(callback->AsObject()), true);
    uint32_t code = static_cast<uint32_t>(ICoAuth::CO_AUTH_EXECUTOR_REGISTER);
    auto service = UserIAM::Common::MakeShared<CoAuthService>(1, true);
    EXPECT_NE(service, nullptr);
    EXPECT_EQ(service->OnRemoteRequest(code, data, reply), 0);
    uint64_t executorIndex = 0;
    EXPECT_EQ(reply.ReadUint64(executorIndex), true);
    EXPECT_NE(executorIndex, 0);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS