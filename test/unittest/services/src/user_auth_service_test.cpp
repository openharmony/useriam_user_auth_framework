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

#include "user_auth_service_test.h"

#include "mock_user_auth_callback.h"
#include "result_code.h"
#include "user_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthServiceTest::SetUpTestCase()
{
}

void UserAuthServiceTest::TearDownTestCase()
{
}

void UserAuthServiceTest::SetUp()
{
}

void UserAuthServiceTest::TearDown()
{
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus, TestSize.Level1)
{
    UserAuthService service(100, true);
    AuthType authType = FACE;
    AuthTrustLevel authTrustLevel = ATL3;
    EXPECT_EQ(CHECK_PERMISSION_FAILED, service.GetAvailableStatus(authType, authTrustLevel));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS