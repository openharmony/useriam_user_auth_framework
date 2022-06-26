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

#include "useridm_ut_test.h"
#include <fstream>
#include <iomanip>
#include <gtest/gtest.h>
#include "useridm_client.h"
#include "useridm_callback_test.h"
#include "useridm_hilog_wrapper.h"

using namespace testing::ext;
namespace OHOS {
namespace UserIAM {
namespace UserIDM {
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
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_001 start");
    UserIDMClient::GetInstance().OpenSession();
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_002, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_002 start");
    UserIDMClient::GetInstance().CloseSession();
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_003, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_003 start");
    AuthType authType = PIN;
    std::shared_ptr<GetInfoCallback> callback = nullptr;
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_003b, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_003b start");
    AuthType authType = PIN;
    std::shared_ptr<GetInfoCallback> callback = std::make_shared<GetInfoCallbackUT>();
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_003c, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_003c start");
    AuthType authType = FACE;
    std::shared_ptr<GetInfoCallback> callback = nullptr;
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_003d, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_003d start");
    AuthType authType = FACE;
    std::shared_ptr<GetInfoCallback> callback = std::make_shared<GetInfoCallbackUT>();
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_004, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_004 start");
    uint32_t userId = 1;
    std::shared_ptr<GetSecInfoCallback> callback = nullptr;
    int32_t ret = UserIDMClient::GetInstance().GetSecInfo(userId, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_004b, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_004b start");
    uint32_t userId = 1;
    std::shared_ptr<GetSecInfoCallback> callback = std::make_shared<GetSecInfoCallbackUT>();
    int32_t ret = UserIDMClient::GetInstance().GetSecInfo(userId, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_005, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_005 start");
    AddCredInfo credInfo;
    credInfo.authType = FACE;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDMClient::GetInstance().OpenSession();
    UserIDMClient::GetInstance().AddCredential(credInfo, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_005b, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_005b start");
    AddCredInfo credInfo;
    credInfo.authType = FACE;
    std::shared_ptr<IDMCallback> callback = std::make_shared<IDMCallbackUT>();
    UserIDMClient::GetInstance().OpenSession();
    UserIDMClient::GetInstance().AddCredential(credInfo, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_005c, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_005c start");
    AddCredInfo credInfo;
    credInfo.authType = PIN;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDMClient::GetInstance().OpenSession();
    UserIDMClient::GetInstance().AddCredential(credInfo, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_005d, TestSize.Level1)
{
    AddCredInfo credInfo;
    credInfo.authType = PIN;
    std::shared_ptr<IDMCallback> callback = std::make_shared<IDMCallbackUT>();
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_005d start");
    UserIDMClient::GetInstance().OpenSession();
    UserIDMClient::GetInstance().AddCredential(credInfo, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_006, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_006 start");
    AddCredInfo credInfo;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDMClient::GetInstance().OpenSession();
    UserIDMClient::GetInstance().UpdateCredential(credInfo, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_006b, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_006b start");
    AddCredInfo credInfo;
    std::shared_ptr<IDMCallback> callback = std::make_shared<IDMCallbackUT>();
    UserIDMClient::GetInstance().OpenSession();
    UserIDMClient::GetInstance().UpdateCredential(credInfo, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_007, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_007 start");
    static uint64_t challenge = 1;
    int32_t ret = UserIDMClient::GetInstance().Cancel(challenge);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_008, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_008 start");
    uint32_t userId = 0;
    std::shared_ptr<IDMCallback> callback = nullptr;
    int32_t ret = UserIDMClient::GetInstance().EnforceDelUser(userId, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_008b, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_008b start");
    uint32_t userId = 1;
    std::shared_ptr<IDMCallback> callback = std::make_shared<IDMCallbackUT>();
    int32_t ret = UserIDMClient::GetInstance().EnforceDelUser(userId, callback);
    EXPECT_EQ(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_009, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_009 start");
    std::vector<uint8_t> authToken;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDMClient::GetInstance().DelUser(authToken, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_009b, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_009b start");
    std::vector<uint8_t> authToken;
    std::shared_ptr<IDMCallback> callback = std::make_shared<IDMCallbackUT>();
    UserIDMClient::GetInstance().DelUser(authToken, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_010, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_010 start");
    uint64_t credentialId = 1;
    std::vector<uint8_t> authToken;
    std::shared_ptr<IDMCallback> callback = nullptr;
    UserIDMClient::GetInstance().DelCred(credentialId, authToken, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_010b, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_010b start");
    uint64_t credentialId = 1;
    std::vector<uint8_t> authToken;
    std::shared_ptr<IDMCallback> callback = std::make_shared<IDMCallbackUT>();
    UserIDMClient::GetInstance().DelCred(credentialId, authToken, callback);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_011, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_011 start");
    AuthType authType = PIN;
    int32_t userId = 0;
    std::shared_ptr<GetInfoCallback> callback = nullptr;
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(userId, authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_011b, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_011b start");
    AuthType authType = PIN;
    int32_t userId = 0;
    std::shared_ptr<GetInfoCallback> callback = std::make_shared<GetInfoCallbackUT>();
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(userId, authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_011c, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_011c start");
    AuthType authType = FACE;
    int32_t userId = 0;
    std::shared_ptr<GetInfoCallback> callback = nullptr;
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(userId, authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIDMUtTest, UserIDMUtTest_011d, TestSize.Level1)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMUtTest_011d start");
    AuthType aut = FACE;
    int32_t userId = 0;
    std::shared_ptr<GetInfoCallback> callback = std::make_shared<GetInfoCallbackUT>();
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(userId, aut, callback);
    EXPECT_NE(SUCCESS, ret);
}
}
}
}
