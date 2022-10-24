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

#include "user_auth_callback_service_test.h"

#include "user_auth_callback_service.h"
#include "iam_ptr.h"
#include "mock_user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserAuthCallbackServiceTest::SetUpTestCase()
{
}

void UserAuthCallbackServiceTest::TearDownTestCase()
{
}

void UserAuthCallbackServiceTest::SetUp()
{
}

void UserAuthCallbackServiceTest::TearDown()
{
}

HWTEST_F(UserAuthCallbackServiceTest, UserAuthCallbackServiceTest001, TestSize.Level0)
{
    int32_t testResult = FAIL;
    Attributes testExtraInfo;

    int32_t testModule = 52334;
    int32_t testAcquireInfo = 57845;

    std::shared_ptr<AuthenticationCallback> authCallback = nullptr;
    auto service = Common::MakeShared<UserAuthCallbackService>(authCallback);
    EXPECT_NE(service, nullptr);
    service->OnResult(testResult, testExtraInfo);
    service->OnAcquireInfo(testModule, testAcquireInfo, testExtraInfo);
}

HWTEST_F(UserAuthCallbackServiceTest, UserAuthCallbackServiceTest002, TestSize.Level0)
{
    int32_t testResult = FAIL;
    Attributes testExtraInfo;

    int32_t testModule = 52334;
    int32_t testAcquireInfo = 57845;

    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(_, _)).Times(1);
    ON_CALL(*authCallback, OnResult)
        .WillByDefault(
            [&testResult](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, testResult);
            }
        );
    EXPECT_CALL(*authCallback, OnAcquireInfo(_, _, _)).Times(1);
    ON_CALL(*authCallback, OnAcquireInfo)
        .WillByDefault(
            [&testModule, &testAcquireInfo](int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) {
                EXPECT_EQ(module, testModule);
                EXPECT_EQ(acquireInfo, testAcquireInfo);
            }
        );
    auto service = Common::MakeShared<UserAuthCallbackService>(authCallback);
    EXPECT_NE(service, nullptr);
    service->OnResult(testResult, testExtraInfo);
    service->OnAcquireInfo(testModule, testAcquireInfo, testExtraInfo);
}

HWTEST_F(UserAuthCallbackServiceTest, UserAuthCallbackServiceTest003, TestSize.Level0)
{
    int32_t testResult = FAIL;
    Attributes testExtraInfo;

    int32_t testModule = 52334;
    int32_t testAcquireInfo = 57845;

    auto identifyCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(identifyCallback, nullptr);
    EXPECT_CALL(*identifyCallback, OnResult(_, _)).Times(1);
    ON_CALL(*identifyCallback, OnResult)
        .WillByDefault(
            [&testResult](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, testResult);
            }
        );
    EXPECT_CALL(*identifyCallback, OnAcquireInfo(_, _, _)).Times(1);
    ON_CALL(*identifyCallback, OnAcquireInfo)
        .WillByDefault(
            [&testModule, &testAcquireInfo](int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) {
                EXPECT_EQ(module, testModule);
                EXPECT_EQ(acquireInfo, testAcquireInfo);
            }
        );
    auto service = Common::MakeShared<UserAuthCallbackService>(identifyCallback);
    EXPECT_NE(service, nullptr);
    service->OnResult(testResult, testExtraInfo);
    service->OnAcquireInfo(testModule, testAcquireInfo, testExtraInfo);
}

HWTEST_F(UserAuthCallbackServiceTest, GetExecutorPropertyCallbackServiceTest001, TestSize.Level0)
{
    int32_t testResult = FAIL;
    Attributes testAttr;

    std::shared_ptr<GetPropCallback> getPropCallback = nullptr;
    auto service = Common::MakeShared<GetExecutorPropertyCallbackService>(getPropCallback);
    EXPECT_NE(service, nullptr);
    service->OnGetExecutorPropertyResult(testResult, testAttr);
}

HWTEST_F(UserAuthCallbackServiceTest, GetExecutorPropertyCallbackServiceTest002, TestSize.Level0)
{
    int32_t testResult = FAIL;
    Attributes testAttr;

    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    EXPECT_CALL(*getPropCallback, OnResult(_, _)).Times(1);
    ON_CALL(*getPropCallback, OnResult)
        .WillByDefault(
            [&testResult](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, testResult);
            }
        );
    auto service = Common::MakeShared<GetExecutorPropertyCallbackService>(getPropCallback);
    EXPECT_NE(service, nullptr);
    service->OnGetExecutorPropertyResult(testResult, testAttr);
}

HWTEST_F(UserAuthCallbackServiceTest, SetExecutorPropertyCallbackServiceTest001, TestSize.Level0)
{
    int32_t testResult = FAIL;

    std::shared_ptr<SetPropCallback> setPropCallback = nullptr;
    auto service = Common::MakeShared<SetExecutorPropertyCallbackService>(setPropCallback);
    EXPECT_NE(service, nullptr);
    service->OnSetExecutorPropertyResult(testResult);
}

HWTEST_F(UserAuthCallbackServiceTest, SetExecutorPropertyCallbackServiceTest002, TestSize.Level0)
{
    int32_t testResult = FAIL;

    auto setPropCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(setPropCallback, nullptr);
    EXPECT_CALL(*setPropCallback, OnResult(_, _)).Times(1);
    ON_CALL(*setPropCallback, OnResult)
        .WillByDefault(
            [&testResult](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, testResult);
            }
        );
    auto service = Common::MakeShared<SetExecutorPropertyCallbackService>(setPropCallback);
    EXPECT_NE(service, nullptr);
    service->OnSetExecutorPropertyResult(testResult);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS