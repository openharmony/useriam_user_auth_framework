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

#include "userauth_test.h"
#include <memory>
#include <iostream>
#include <gtest/gtest.h>
#include "user_auth.h"
#include "userauth_callback.h"
#include "userauth_info.h"
#include "common_info.h"
#include "userauth.h"
#include "userauth_defines.h"

using namespace testing::ext;
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UseriamUtTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void UseriamUtTest::SetUpTestCase(void)
{
}

void UseriamUtTest::TearDownTestCase(void)
{
}

void UseriamUtTest::SetUp()
{
}

void UseriamUtTest::TearDown()
{
}

class TestUserAuthCallback : public UserAuthCallback {
public:
    TestUserAuthCallback() = default;
    virtual ~TestUserAuthCallback() = default;

    void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) override;
    void onResult(const int32_t result, const AuthResult &extraInfo) override;
};

class TestGetPropCallback : public GetPropCallback {
public:
    TestGetPropCallback() = default;
    virtual ~TestGetPropCallback() = default;

    void onGetProperty(const ExecutorProperty result) override;
};

class TestSetPropCallback : public SetPropCallback {
public:
    TestSetPropCallback() = default;
    virtual ~TestSetPropCallback() = default;

    void onSetProperty(const int32_t result) override;
};

void TestUserAuthCallback::onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo)
{
    std::cout << "onAcquireInfo callback" << std::endl;
}

void TestUserAuthCallback::onResult(const int32_t result, const AuthResult &extraInfo)
{
    std::cout << "onResult callback" << std::endl;
}

void TestGetPropCallback::onGetProperty(const ExecutorProperty result)
{
    std::cout << "onGetProperty callback" << std::endl;
}

void TestSetPropCallback::onSetProperty(const int32_t result)
{
    std::cout << "onSetProperty callback" << std::endl;
}

HWTEST_F(UseriamUtTest, UseriamUtTest_001, TestSize.Level1)
{
    AuthType authType = FACE;
    AuthTrustLevel authTrustLevel = ATL1;
    EXPECT_NE(0, UserAuthNative::GetInstance().GetAvailableStatus(authType, authTrustLevel));
}

HWTEST_F(UseriamUtTest, UseriamUtTest_002, TestSize.Level1)
{
    GetPropertyRequest request;
    request.authType = FACE;
    request.keys.push_back(1);
    request.keys.push_back(3);
    std::shared_ptr<TestGetPropCallback> callback = std::make_shared<TestGetPropCallback>();
    UserAuthNative::GetInstance().GetProperty(request, callback);
}

HWTEST_F(UseriamUtTest, UseriamUtTest_003, TestSize.Level1)
{
    SetPropertyRequest request;
    request.authType = FACE;
    request.key = INIT_ALGORITHM;
    uint8_t i = 123;
    request.setInfo.push_back(i);
    std::shared_ptr<TestSetPropCallback> callback = std::make_shared<TestSetPropCallback>();
    UserAuthNative::GetInstance().SetProperty(request, callback);
}

HWTEST_F(UseriamUtTest, UseriamUtTest_004, TestSize.Level1)
{
    uint64_t challenge = 001;
    AuthType authType = FACE;
    AuthTrustLevel authTrustLevel = ATL1;
    std::shared_ptr<UserAuthCallback> callback = std::make_shared<TestUserAuthCallback>();
    EXPECT_EQ(0, UserAuthNative::GetInstance().Auth(challenge, authType, authTrustLevel, callback));
}

HWTEST_F(UseriamUtTest, UseriamUtTest_005, TestSize.Level1)
{
    int32_t userId = 0;
    uint64_t challenge = 001;
    AuthType authType = FACE;
    AuthTrustLevel authTrustLevel = ATL1;
    std::shared_ptr<UserAuthCallback> callback = std::make_shared<TestUserAuthCallback>();
    EXPECT_EQ(0, UserAuthNative::GetInstance().AuthUser(userId, challenge, authType, authTrustLevel, callback));
}

HWTEST_F(UseriamUtTest, UseriamUtTest_006, TestSize.Level1)
{
    uint64_t contextId = 0;
    EXPECT_NE(0, UserAuthNative::GetInstance().CancelAuth(contextId));
}

HWTEST_F(UseriamUtTest, UseriamUtTest_007, TestSize.Level1)
{
    GetPropertyRequest request;
    int32_t userId = 100;
    request.authType = FACE;
    request.keys.push_back(1);
    request.keys.push_back(3);
    std::shared_ptr<TestGetPropCallback> callback = std::make_shared<TestGetPropCallback>();
    UserAuth::GetInstance().GetProperty(userId, request, callback);
}

HWTEST_F(UseriamUtTest, UseriamUtTest_008, TestSize.Level1)
{
    SetPropertyRequest request;
    int32_t userId = 100;
    request.authType = FACE;
    request.key = INIT_ALGORITHM;
    uint8_t i = 123;
    request.setInfo.push_back(i);
    std::shared_ptr<TestSetPropCallback> callback = std::make_shared<TestSetPropCallback>();
    UserAuth::GetInstance().SetProperty(userId, request, callback);
}

HWTEST_F(UseriamUtTest, UseriamUtTest_009, TestSize.Level1)
{
    int32_t userId = 0;
    uint64_t challenge = 001;
    AuthType authType = FACE;
    AuthTrustLevel authTrustLevel = ATL1;
    std::shared_ptr<UserAuthCallback> callback = std::make_shared<TestUserAuthCallback>();
    EXPECT_EQ(0, UserAuth::GetInstance().AuthUser(userId, challenge, authType, authTrustLevel, callback));
}

HWTEST_F(UseriamUtTest, UseriamUtTest_010, TestSize.Level1)
{
    uint64_t contextId = 0;
    EXPECT_NE(0, UserAuth::GetInstance().CancelAuth(contextId));
}
}
}
}
