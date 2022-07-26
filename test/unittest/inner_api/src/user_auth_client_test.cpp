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

#include "user_auth_client_test.h"

#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "iam_ptr.h"
#include "user_auth_client.h"
#include "mock_user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthClientTest::SetUpTestCase()
{
    static const char *PERMS[] = {
        "ohos.permission.ACCESS_USER_AUTH_INTERNAL",
        "ohos.permission.ACCESS_BIOMETRIC"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = PERMS,
        .acls = nullptr,
        .processName = "useriam",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
}

void UserAuthClientTest::TearDownTestCase()
{
}

void UserAuthClientTest::SetUp()
{
}

void UserAuthClientTest::TearDown()
{
}

HWTEST_F(UserAuthClientTest, UserAuthClientGetProperty, TestSize.Level0)
{
    int32_t userId = 100;
    GetPropertyRequest request = {};
    auto callback = UserIAM::Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(1);
    UserAuthClient::GetInstance().GetProperty(userId, request, callback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS