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
using namespace OHOS::UserIam::UserAuth;
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserIdmUtTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void UserIdmUtTest::SetUpTestCase(void)
{
}

void UserIdmUtTest::TearDownTestCase(void)
{
}

void UserIdmUtTest::SetUp()
{
}

void UserIdmUtTest::TearDown()
{
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_001, TestSize.Level0)
{
    int32_t userId = 0;
    UserIdm::GetInstance().OpenSession(userId);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_002, TestSize.Level0)
{
    int32_t userId = 0;
    UserIdm::GetInstance().CloseSession(userId);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_003, TestSize.Level0)
{
    int32_t userId = 0;
    AddCredInfo credInfo;
    credInfo.authType = FACE;
    std::shared_ptr<IdmCallback> callback = nullptr;
    UserIdm::GetInstance().OpenSession(userId);
    UserIdm::GetInstance().AddCredential(userId, credInfo, callback);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_003b, TestSize.Level0)
{
    int32_t userId = 0;
    AddCredInfo credInfo;
    credInfo.authType = FACE;
    std::shared_ptr<IdmCallback> callback = std::make_shared<IDMCallbackUT>();
    UserIdm::GetInstance().OpenSession(userId);
    UserIdm::GetInstance().AddCredential(userId, credInfo, callback);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_004, TestSize.Level0)
{
    int32_t userId = 0;
    AddCredInfo credInfo;
    std::shared_ptr<IdmCallback> callback = nullptr;
    UserIdm::GetInstance().OpenSession(userId);
    UserIdm::GetInstance().UpdateCredential(userId, credInfo, callback);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_004b, TestSize.Level0)
{
    int32_t userId = 0;
    AddCredInfo credInfo;
    std::shared_ptr<IdmCallback> callback = std::make_shared<IDMCallbackUT>();
    UserIdm::GetInstance().OpenSession(userId);
    UserIdm::GetInstance().UpdateCredential(userId, credInfo, callback);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_005, TestSize.Level0)
{
    int32_t userId = 0;
    int32_t ret = UserIdm::GetInstance().Cancel(userId);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_006, TestSize.Level0)
{
    int32_t userId = 0;
    std::vector<uint8_t> authToken;
    std::shared_ptr<IdmCallback> callback = nullptr;
    UserIdm::GetInstance().DelUser(userId, authToken, callback);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_006b, TestSize.Level0)
{
    int32_t userId = 0;
    std::vector<uint8_t> authToken;
    std::shared_ptr<IdmCallback> callback = std::make_shared<IDMCallbackUT>();
    UserIdm::GetInstance().DelUser(userId, authToken, callback);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_007, TestSize.Level0)
{
    int32_t userId = 0;
    uint64_t credentialId = 1;
    std::vector<uint8_t> authToken;
    std::shared_ptr<IdmCallback> callback = nullptr;
    UserIdm::GetInstance().DelCredential(userId, credentialId, authToken, callback);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_007b, TestSize.Level0)
{
    int32_t userId = 0;
    uint64_t credentialId = 1;
    std::vector<uint8_t> authToken;
    std::shared_ptr<IdmCallback> callback = std::make_shared<IDMCallbackUT>();
    UserIdm::GetInstance().DelCredential(userId, credentialId, authToken, callback);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_008, TestSize.Level0)
{
    int32_t userId = 0;
    AuthType authType = PIN;
    std::shared_ptr<GetInfoCallback> callback = nullptr;
    int32_t ret = UserIdm::GetInstance().GetAuthInfo(userId, authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_008b, TestSize.Level0)
{
    int32_t userId = 0;
    AuthType authType = PIN;
    std::shared_ptr<GetInfoCallback> callback = std::make_shared<GetInfoCallbackUT>();
    int32_t ret = UserIdm::GetInstance().GetAuthInfo(userId, authType, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_009, TestSize.Level0)
{
    uint32_t userId = 0;
    std::shared_ptr<GetSecInfoCallback> callback = nullptr;
    int32_t ret = UserIdm::GetInstance().GetSecInfo(userId, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_009b, TestSize.Level0)
{
    uint32_t userId = 0;
    std::shared_ptr<GetSecInfoCallback> callback = std::make_shared<GetSecInfoCallbackUT>();
    int32_t ret = UserIdm::GetInstance().GetSecInfo(userId, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_010, TestSize.Level0)
{
    uint32_t userId = 0;
    std::shared_ptr<IdmCallback> callback = nullptr;
    int32_t ret = UserIdm::GetInstance().EnforceDelUser(userId, callback);
    EXPECT_NE(SUCCESS, ret);
}

HWTEST_F(UserIdmUtTest, UserIdmUtTest_010b, TestSize.Level0)
{
    uint32_t userId = 0;
    std::shared_ptr<IdmCallback> callback = std::make_shared<IDMCallbackUT>();
    int32_t ret = UserIdm::GetInstance().EnforceDelUser(userId, callback);
    EXPECT_EQ(SUCCESS, ret);
}
}
}
}
