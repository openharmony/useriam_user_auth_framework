/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "user_idm_ut_test.h"
#include <fstream>
#include <iomanip>
#include <gtest/gtest.h>
#include "common_info.h"
#include "user_idm.h"
#include "user_idm_defines.h"
#include "user_idm_callback_test.h"

using namespace testing::ext;
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserIDMUtTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void UserIDMUtTest::SetUpTestCase(void)
{
}

void UserIDMUtTest::TearDownTestCase(void)
{
}

void UserIDMUtTest::SetUp()
{
}

void UserIDMUtTest::TearDown()
{
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_001, TestSize.Level1)
{
    int32_t userId = 0;
    UserIDM::GetInstance().OpenSession(userId);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_002, TestSize.Level1)
{
    int32_t userId = 0;
    UserIDM::GetInstance().CloseSession(userId);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_003, TestSize.Level1)
{
    int32_t userId = 0;
    AddCredInfo credInfo;
    credInfo.authType = FACE;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDM::GetInstance().OpenSession(userId);
    UserIDM::GetInstance().AddCredential(userId, credInfo, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_004, TestSize.Level1)
{
    int32_t userId = 0;
    AddCredInfo credInfo;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDM::GetInstance().OpenSession(userId);
    UserIDM::GetInstance().UpdateCredential(userId, credInfo, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_005, TestSize.Level1)
{
    int32_t userId = 0;
    int32_t ret = UserIDM::GetInstance().Cancel(userId);
    EXPECT_EQ(0, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_006, TestSize.Level1)
{
    int32_t userId = 0;
    std::vector<uint8_t> authToken;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDM::GetInstance().DelUser(userId, authToken, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_007, TestSize.Level1)
{
    int32_t userId = 0;
    uint64_t credentialId = 1;
    std::vector<uint8_t> authToken;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDM::GetInstance().DelCredential(userId, credentialId, authToken, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_008, TestSize.Level1)
{
    int32_t userId = 0;
    AuthType authType = PIN;
    std::shared_ptr<GetInfoCallback> callback = nullptr;
    int32_t ret = UserIDM::GetInstance().GetAuthInfo(userId, authType, callback);
    EXPECT_EQ(0, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_009, TestSize.Level1)
{
    uint32_t userId = 0;
    std::shared_ptr<GetSecInfoCallback> callback = nullptr;
    int32_t ret = UserIDM::GetInstance().GetSecInfo(userId, callback);
    EXPECT_EQ(0, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_010, TestSize.Level1)
{
    uint32_t userId = 0;
    std::shared_ptr<IDMCallback> callback = nullptr;
    int32_t ret = UserIDM::GetInstance().EnforceDelUser(userId, callback);
    EXPECT_EQ(0, ret);
}
}
}
}
