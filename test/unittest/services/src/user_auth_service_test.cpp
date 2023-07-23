/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include <future>

#include "iam_common_defines.h"
#include "iam_ptr.h"

#include "executor_messenger_service.h"
#include "mock_context.h"
#include "mock_iuser_auth_interface.h"
#include "mock_ipc_common.h"
#include "mock_user_auth_callback.h"
#include "mock_user_auth_service.h"
#include "mock_resource_node.h"
#include "resource_node_pool.h"
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
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void UserAuthServiceTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus001, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 8;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL3;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAuthTrustLevel(_, _, _))
        .Times(1)
        .WillOnce(
            [](int32_t userId, HdiAuthType authType, uint32_t &authTrustLevel) {
                authTrustLevel = ATL1;
                return HDF_SUCCESS;
            }
        );
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_NE(SUCCESS, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 8;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = static_cast<AuthTrustLevel>(90000);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(TRUST_LEVEL_NOT_SUPPORT, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));

    testAuthTrustLevel = ATL2;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAuthTrustLevel(_, _, _)).Times(1);
    ON_CALL(*mockHdi, GetAuthTrustLevel)
        .WillByDefault(
            [](int32_t userId, HdiAuthType authType, uint32_t &authTrustLevel) {
                authTrustLevel = static_cast<AuthTrustLevel>(0);
                return SUCCESS;
            }
        );
    EXPECT_EQ(TRUST_LEVEL_NOT_SUPPORT, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus003, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 8;
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAuthTrustLevel(_, _, _)).WillRepeatedly([]() {
        return NOT_ENROLLED;
    });
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(NOT_ENROLLED, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));

    testApiVersion = 9;
    EXPECT_EQ(NOT_ENROLLED, service.GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetAvailableStatus004, TestSize.Level0)
{
    int32_t testApiVersion = 8;
    AuthType testAuthType = PIN;
    AuthTrustLevel testAuthTrustLevel = ATL2;

    auto service = Common::MakeShared<UserAuthService>(100, true);
    EXPECT_NE(service, nullptr);
    int32_t ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);

    testAuthType = FACE;
    ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    testAuthTrustLevel = static_cast<AuthTrustLevel>(0);
    ret = service->GetAvailableStatus(testApiVersion, testAuthType, testAuthTrustLevel);
    EXPECT_EQ(ret, TRUST_LEVEL_NOT_SUPPORT);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty001, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 123;
    AuthType testAuthType = PIN;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).Times(1);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _)).Times(2);
    sptr<GetExecutorPropertyCallbackInterface> callbackInterface = testCallback;
    service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetProperty002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 123;
    AuthType testAuthType = PIN;
    std::vector<Attributes::AttributeKey> testKeys = {Attributes::ATTR_PIN_SUB_TYPE, Attributes::ATTR_SIGNATURE};
    sptr<MockGetExecutorPropertyCallback> testCallback(nullptr);
    sptr<GetExecutorPropertyCallbackInterface> callbackInterface = testCallback;
    service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).Times(2);
    ON_CALL(*mockHdi, GetCredential)
        .WillByDefault(
            [](int32_t userId, HdiAuthType authType, std::vector<HdiCredentialInfo> &infos) {
                HdiCredentialInfo tempInfo = {
                    .credentialId = 1,
                    .executorIndex = 2,
                    .templateId = 3,
                    .authType = static_cast<HdiAuthType>(1),
                    .executorMatcher = 2,
                    .executorSensorHint = 3,
                };
                infos.push_back(tempInfo);
                return HDF_SUCCESS;
            }
        );
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    EXPECT_CALL(*node, GetProperty(_, _))
        .Times(2)
        .WillOnce(Return(FAIL))
        .WillOnce(Return(SUCCESS));
    testCallback = sptr<MockGetExecutorPropertyCallback>(new (std::nothrow) MockGetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnGetExecutorPropertyResult(_, _)).Times(2);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    callbackInterface = testCallback;
    service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    service.GetProperty(testUserId, testAuthType, testKeys, callbackInterface);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetProperty001, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 124;
    AuthType testAuthType = PIN;
    Attributes testAttr;
    sptr<MockSetExecutorPropertyCallback> testCallback(new (std::nothrow) MockSetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnSetExecutorPropertyResult(_)).Times(2);
    sptr<SetExecutorPropertyCallbackInterface> callbackInterface = testCallback;
    service.SetProperty(testUserId, testAuthType, testAttr, callbackInterface);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    service.SetProperty(testUserId, testAuthType, testAttr, callbackInterface);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetProperty002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 124;
    AuthType testAuthType = PIN;
    Attributes testAttr;
    sptr<MockSetExecutorPropertyCallback> testCallback(nullptr);
    sptr<SetExecutorPropertyCallbackInterface> callbackInterface = testCallback;
    service.SetProperty(testUserId, testAuthType, testAttr, callbackInterface);

    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(2);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    MockResourceNode *node = static_cast<MockResourceNode *>(resourceNode.get());
    EXPECT_CALL(*node, SetProperty(_))
        .Times(2)
        .WillOnce(Return(FAIL))
        .WillOnce(Return(SUCCESS));
    testCallback = sptr<MockSetExecutorPropertyCallback>(new (std::nothrow) MockSetExecutorPropertyCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnSetExecutorPropertyResult(_)).Times(2);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    callbackInterface = testCallback;
    service.SetProperty(testUserId, testAuthType, testAttr, callbackInterface);
    service.SetProperty(testUserId, testAuthType, testAttr, callbackInterface);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth001, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _))
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, HDF_FAILURE);
            }
        );

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginAuthenticationV1_1(_, _, _)).WillOnce(Return(HDF_FAILURE));

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.Auth(testApiVersion, testChallenge, testAuthType,
        testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(nullptr);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.Auth(testApiVersion, testChallenge, testAuthType,
        testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);

    testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(2);
    testAuthTrustLevel = static_cast<AuthTrustLevel>(90000);
    callbackInterface = testCallback;
    contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);

    testAuthType = PIN;
    testAuthTrustLevel = ATL1;
    contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth003, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = PIN;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(4);

    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.Auth(testApiVersion, testChallenge, testAuthType,
        testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);

    testAuthType = FACE;
    contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginAuthenticationV1_1(_, _, _)).Times(2).WillRepeatedly(Return(NOT_ENROLLED));
    contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);

    testApiVersion = 8;
    contextId = service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);

    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuth004, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testApiVersion = 9;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    std::shared_ptr<Context> context = nullptr;

    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _))
        .WillOnce(
            [&context](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
                if (context != nullptr) {
                    context->Stop();
                }
            }
        );

    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginAuthenticationV1_1(_, _, _))
        .WillRepeatedly(
            [&context](uint64_t contextId, const HdiAuthSolution &param, std::vector<HdiScheduleInfo> &scheduleInfos) {
                HdiScheduleInfo scheduleInfo = {};
                scheduleInfo.authType = HdiAuthType::FACE;
                scheduleInfo.scheduleId = 20;
                HdiExecutorInfo executorInfo = {};
                executorInfo.executorIndex = 60;
                scheduleInfo.executors.push_back(executorInfo);
                scheduleInfos.push_back(scheduleInfo);
                context = ContextPool::Instance().Select(contextId).lock();
                return HDF_SUCCESS;
            }
        );
    
    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _)).WillOnce(Return(HDF_SUCCESS));
    std::promise<void> promise;
    EXPECT_CALL(*mockHdi, CancelAuthentication(_))
        .WillOnce(
            [&promise](uint64_t contextId) {
                promise.set_value();
                return HDF_SUCCESS;
            }
        );

    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(60));
    EXPECT_CALL(*resourceNode, GetAuthType()).WillRepeatedly(Return(FACE));
    EXPECT_CALL(*resourceNode, GetExecutorRole()).WillRepeatedly(Return(ALL_IN_ONE));
    EXPECT_CALL(*resourceNode, GetExecutorMatcher()).WillRepeatedly(Return(0));
    EXPECT_CALL(*resourceNode, GetExecutorPublicKey()).WillRepeatedly(Return(std::vector<uint8_t>()));
    EXPECT_CALL(*resourceNode, BeginExecute(_, _, _))
        .WillOnce(
            [](uint64_t scheduleId, const std::vector<uint8_t> &publicKey, const Attributes &command) {
                auto messenger = ExecutorMessengerService::GetInstance();
                EXPECT_NE(messenger, nullptr);
                auto finalResult = Common::MakeShared<Attributes>();
                EXPECT_NE(finalResult, nullptr);
                std::vector<uint8_t> scheduleResult = {1, 2, 3, 4};
                EXPECT_TRUE(finalResult->SetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult));
                EXPECT_EQ(messenger->Finish(20, ALL_IN_ONE, SUCCESS, finalResult), SUCCESS);
                return SUCCESS;
            }
        );
    
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));

    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    service.Auth(testApiVersion, testChallenge, testAuthType, testAuthTrustLevel, callbackInterface);
    promise.get_future().get();

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(60));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser001, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 125;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginAuthenticationV1_1(_, _, _)).Times(1);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.AuthUser(testUserId, testChallenge, testAuthType,
        testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser002, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 125;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    sptr<MockUserAuthCallback> testCallback(nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.AuthUser(testUserId, testChallenge, testAuthType,
        testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);

    testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    testAuthTrustLevel = static_cast<AuthTrustLevel>(90000);
    callbackInterface = testCallback;
    contextId = service.AuthUser(testUserId, testChallenge, testAuthType, testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthUser003, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t testUserId = 125;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    AuthTrustLevel testAuthTrustLevel = ATL2;
    std::shared_ptr<Context> context = nullptr;

    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
            }
        )
        .WillOnce(
            [&context](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
                if (context != nullptr) {
                    context->Stop();
                }
            }
        );

    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.AuthUser(testUserId, testChallenge, testAuthType,
        testAuthTrustLevel, callbackInterface);
    EXPECT_EQ(contextId, 0);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginAuthenticationV1_1(_, _, _))
        .WillRepeatedly(
            [&context](uint64_t contextId, const HdiAuthSolution &param, std::vector<HdiScheduleInfo> &scheduleInfos) {
                HdiScheduleInfo scheduleInfo = {};
                scheduleInfo.authType = HdiAuthType::FACE;
                scheduleInfo.scheduleId = 30;
                HdiExecutorInfo executorInfo = {};
                executorInfo.executorIndex = 60;
                scheduleInfo.executors.push_back(executorInfo);
                scheduleInfos.push_back(scheduleInfo);
                context = ContextPool::Instance().Select(contextId).lock();
                return HDF_SUCCESS;
            }
        );
    
    EXPECT_CALL(*mockHdi, UpdateAuthenticationResult(_, _, _)).WillOnce(Return(HDF_SUCCESS));
    std::promise<void> promise;
    EXPECT_CALL(*mockHdi, CancelAuthentication(_))
        .WillOnce(
            [&promise](uint64_t contextId) {
                promise.set_value();
                return HDF_SUCCESS;
            }
        );

    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(60));
    EXPECT_CALL(*resourceNode, GetAuthType()).WillRepeatedly(Return(FACE));
    EXPECT_CALL(*resourceNode, GetExecutorRole()).WillRepeatedly(Return(ALL_IN_ONE));
    EXPECT_CALL(*resourceNode, GetExecutorMatcher()).WillRepeatedly(Return(0));
    EXPECT_CALL(*resourceNode, GetExecutorPublicKey()).WillRepeatedly(Return(std::vector<uint8_t>()));
    EXPECT_CALL(*resourceNode, BeginExecute(_, _, _))
        .WillOnce(
            [](uint64_t scheduleId, const std::vector<uint8_t> &publicKey, const Attributes &command) {
                auto messenger = ExecutorMessengerService::GetInstance();
                EXPECT_NE(messenger, nullptr);
                auto finalResult = Common::MakeShared<Attributes>();
                EXPECT_NE(finalResult, nullptr);
                std::vector<uint8_t> scheduleResult = {1, 2, 3, 4};
                EXPECT_TRUE(finalResult->SetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult));
                EXPECT_EQ(messenger->Finish(30, ALL_IN_ONE, SUCCESS, finalResult), SUCCESS);
                return SUCCESS;
            }
        );
    
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));

    contextId = service.AuthUser(testUserId, testChallenge, testAuthType, testAuthTrustLevel, callbackInterface);
    promise.get_future().get();

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(60));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify001, TestSize.Level0)
{
    UserAuthService service(100, true);
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockHdi, BeginIdentificationV1_1(_, _, _, _, _)).Times(1);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.Identify(testChallenge, testAuthType, callbackInterface);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify002, TestSize.Level0)
{
    UserAuthService service(100, true);
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    sptr<MockUserAuthCallback> testCallback(nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.Identify(testChallenge, testAuthType, callbackInterface);
    EXPECT_EQ(contextId, 0);

    testCallback = sptr<MockUserAuthCallback>(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    testAuthType = PIN;
    callbackInterface = testCallback;
    contextId = service.Identify(testChallenge, testAuthType, callbackInterface);
    EXPECT_EQ(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceIdentify003, TestSize.Level0)
{
    UserAuthService service(100, true);
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    AuthType testAuthType = FACE;
    std::shared_ptr<Context> context = nullptr;

    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
            }
        )
        .WillOnce(
            [&context](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
                if (context != nullptr) {
                    context->Stop();
                }
            }
        );

    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    uint64_t contextId = service.Identify(testChallenge, testAuthType, callbackInterface);
    EXPECT_EQ(contextId, 0);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginIdentificationV1_1(_, _, _, _, _))
        .WillRepeatedly(
            [&context](uint64_t contextId, HdiAuthType authType, const std::vector<uint8_t> &challenge,
                uint32_t executorId, HdiScheduleInfo &scheduleInfo) {
                scheduleInfo.authType = HdiAuthType::FACE;
                scheduleInfo.scheduleId = 50;
                HdiExecutorInfo executorInfo = {};
                executorInfo.executorIndex = 60;
                scheduleInfo.executors.push_back(executorInfo);
                context = ContextPool::Instance().Select(contextId).lock();
                return HDF_SUCCESS;
            }
        );
    
    EXPECT_CALL(*mockHdi, UpdateIdentificationResult(_, _, _)).WillOnce(Return(HDF_SUCCESS));
    std::promise<void> promise;
    EXPECT_CALL(*mockHdi, CancelIdentification(_))
        .WillOnce(
            [&promise](uint64_t contextId) {
                promise.set_value();
                return HDF_SUCCESS;
            }
        );

    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(60));
    EXPECT_CALL(*resourceNode, GetAuthType()).WillRepeatedly(Return(FACE));
    EXPECT_CALL(*resourceNode, GetExecutorRole()).WillRepeatedly(Return(ALL_IN_ONE));
    EXPECT_CALL(*resourceNode, GetExecutorMatcher()).WillRepeatedly(Return(0));
    EXPECT_CALL(*resourceNode, GetExecutorPublicKey()).WillRepeatedly(Return(std::vector<uint8_t>()));
    EXPECT_CALL(*resourceNode, BeginExecute(_, _, _))
        .WillOnce(
            [](uint64_t scheduleId, const std::vector<uint8_t> &publicKey, const Attributes &command) {
                auto messenger = ExecutorMessengerService::GetInstance();
                EXPECT_NE(messenger, nullptr);
                auto finalResult = Common::MakeShared<Attributes>();
                EXPECT_NE(finalResult, nullptr);
                std::vector<uint8_t> scheduleResult = {1, 2, 3, 4};
                EXPECT_TRUE(finalResult->SetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult));
                EXPECT_EQ(messenger->Finish(50, ALL_IN_ONE, SUCCESS, finalResult), SUCCESS);
                return SUCCESS;
            }
        );
    
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));

    contextId = service.Identify(testChallenge, testAuthType, callbackInterface);
    promise.get_future().get();

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(60));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCancelAuthOrIdentify_001, TestSize.Level0)
{
    UserAuthService service(100, true);
    uint64_t testContextId = 12355236;
    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId), CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId), CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCancelAuthOrIdentify_002, TestSize.Level0)
{
    UserAuthService service(100, true);
    uint64_t testContextId = 12355236;

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    uint32_t tokenId = 0;
    IpcCommon::SetAccessTokenId(tokenId, true);
    auto context = Common::MakeShared<MockContext>();
    EXPECT_NE(context, nullptr);
    EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(testContextId));
    EXPECT_CALL(*context, GetLatestError()).WillRepeatedly(Return(GENERAL_ERROR));
    
    EXPECT_TRUE(ContextPool::Instance().Insert(context));
    
    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId), CHECK_PERMISSION_FAILED);
    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId), CHECK_PERMISSION_FAILED);
    IpcCommon::SetAccessTokenId(tokenId, false);

    EXPECT_EQ(service.CancelAuthOrIdentify(testContextId), CHECK_PERMISSION_FAILED);
    EXPECT_TRUE(ContextPool::Instance().Delete(testContextId));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceGetVersion, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t version = -1;
    EXPECT_EQ(service.GetVersion(version), CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.GetVersion(version), SUCCESS);
    EXPECT_EQ(version, 1);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget1, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t apiVersion = 10;
    AuthParam authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authType.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParam widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";

    sptr<UserAuthCallbackInterface> testUserAuthCallback = nullptr;
    EXPECT_EQ(service.AuthWidget(apiVersion, authParam, widgetParam, testUserAuthCallback), (uint64_t)0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget2, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t apiVersion = 10;
    AuthParam authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authType.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParam widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";

    sptr<UserAuthCallbackInterface> testUserAuthCallback = new MockUserAuthCallback();
    EXPECT_NE(testUserAuthCallback, nullptr);

    std::shared_ptr<Context> context = nullptr;

    int32_t testUserId = 0;
    IpcCommon::GetCallingUserId(service, testUserId);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*mockHdi, BeginAuthenticationV1_1(_, _, _))
    .WillRepeatedly(
        [&context](uint64_t contextId, const HdiAuthSolution &param, std::vector<HdiScheduleInfo> &scheduleInfos) {
            HdiScheduleInfo scheduleInfo = {};
            scheduleInfo.authType = HdiAuthType::FACE;
            scheduleInfo.scheduleId = 20;
            HdiExecutorInfo executorInfo = {};
            executorInfo.executorIndex = 60;
            scheduleInfo.executors.push_back(executorInfo);
            scheduleInfos.push_back(scheduleInfo);
            context = ContextPool::Instance().Select(contextId).lock();
            return HDF_SUCCESS;
        }
    );
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testUserAuthCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget3, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t apiVersion = 10;
    AuthParam authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authType.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParam widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;

    sptr<UserAuthCallbackInterface> testUserAuthCallback = new MockUserAuthCallback();
    EXPECT_NE(testUserAuthCallback, nullptr);
    int32_t testUserId = 0;
    IpcCommon::GetCallingUserId(service, testUserId);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testUserAuthCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);

    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.AuthWidget(apiVersion, authParam, widgetParam, testUserAuthCallback), (uint64_t)0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice1, TestSize.Level0)
{
    UserAuthService service(100, true);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t conxtId = service.Notice(NoticeType::WIDGET_NOTICE, "PIN");
    EXPECT_NE(conxtId, ResultCode::SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice2, TestSize.Level0)
{
    UserAuthService service(100, true);
    int32_t conxtId = service.Notice(NoticeType::WIDGET_NOTICE, "PIN");
    EXPECT_EQ(conxtId, ResultCode::CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback1, TestSize.Level0)
{
    UserAuthService service(100, true);
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback2, TestSize.Level0)
{
    UserAuthService service(100, true);
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback3, TestSize.Level0)
{
    UserAuthService service(100, true);
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t testUserId = 0;
    IpcCommon::GetCallingUserId(service, testUserId);
    EXPECT_EQ(service.RegisterWidgetCallback(2, testCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback4, TestSize.Level0)
{
    UserAuthService service(100, true);
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t testUserId = 0;
    IpcCommon::GetCallingUserId(service, testUserId);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS