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

#include "co_auth_client_test.h"

#include "file_ex.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "co_auth_client.h"
#include "iam_ptr.h"
#include "mock_executor_register_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void CoAuthClientTest::SetUpTestCase()
{
    static const char *PERMS[] = {
        "ohos.permission.ACCESS_AUTH_RESPOOL"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = PERMS,
        .acls = nullptr,
        .processName = "useriam",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    SaveStringToFile("/sys/fs/selinux/enforce", "0");
}

void CoAuthClientTest::TearDownTestCase()
{
}

void CoAuthClientTest::SetUp()
{
}

void CoAuthClientTest::TearDown()
{
}

HWTEST_F(CoAuthClientTest, CoAuthClientRegister, TestSize.Level0)
{
    static ExecutorInfo testInfo = {};
    testInfo.authType = PIN;
    testInfo.executorRole = COLLECTOR;
    testInfo.executorSensorHint = 11;
    testInfo.executorMatcher = 22;
    testInfo.esl = ESL1;
    testInfo.publicKey = {1, 2, 3, 4};

    auto testCallback = Common::MakeShared<MockExecutorRegisterCallback>();
    EXPECT_NE(testCallback, nullptr);
    CoAuthClient::GetInstance().Register(testInfo, testCallback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS