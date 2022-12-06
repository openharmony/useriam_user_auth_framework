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

#include "user_idm_service_test.h"

#include <future>

#include "iam_common_defines.h"
#include "iam_ptr.h"

#include "context_pool.h"
#include "executor_messenger_service.h"
#include "mock_context.h"
#include "mock_ipc_common.h"
#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "mock_user_idm_callback.h"
#include "resource_node_pool.h"
#include "user_idm_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

using HdiCredentialInfo = OHOS::HDI::UserAuth::V1_0::CredentialInfo;
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V1_0::EnrolledInfo;
using HdiExecutorInfo = OHOS::HDI::UserAuth::V1_0::ExecutorInfo;
using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;
using HdiPinSubType = OHOS::HDI::UserAuth::V1_0::PinSubType;
using HdiEnrollParam = OHOS::HDI::UserAuth::V1_0::EnrollParam;
using HdiScheduleInfo = OHOS::HDI::UserAuth::V1_0::ScheduleInfo;

void UserIdmServiceTest::SetUpTestCase()
{
}

void UserIdmServiceTest::TearDownTestCase()
{
}

void UserIdmServiceTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void UserIdmServiceTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceOpenSession_001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, OpenSession(_, _)).Times(1);
    ON_CALL(*mockHdi, OpenSession)
        .WillByDefault(
            [&testChallenge](int32_t userId, std::vector<uint8_t> &challenge) {
                challenge = testChallenge;
                return HDF_SUCCESS;
            }
        );
    std::vector<uint8_t> challenge;
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    int32_t ret = service.OpenSession(testUserId, challenge);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_THAT(challenge, ElementsAreArray(testChallenge));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceOpenSession_002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    std::vector<uint8_t> testChallenge = {1, 2, 3, 4};

    std::vector<uint8_t> challenge;
    int32_t ret = service.OpenSession(testUserId, challenge);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    auto context = Common::MakeShared<MockContext>();
    EXPECT_NE(context, nullptr);
    EXPECT_CALL(*context, GetContextType()).WillRepeatedly(Return(CONTEXT_ENROLL));
    EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(2345));
    EXPECT_CALL(*context, Stop()).WillRepeatedly(Return(true));
    EXPECT_TRUE(ContextPool::Instance().Insert(context));

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, OpenSession(_, _))
        .Times(3)
        .WillOnce(Return(HDF_SUCCESS))
        .WillOnce(Return(HDF_SUCCESS))
        .WillOnce(Return(HDF_FAILURE));
    
    EXPECT_EQ(service.OpenSession(testUserId, challenge), SUCCESS);
    EXPECT_EQ(service.OpenSession(testUserId, challenge), SUCCESS);
    EXPECT_EQ(service.OpenSession(testUserId, challenge), GENERAL_ERROR);

    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceCloseSession, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 3546;

    service.CloseSession(testUserId);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CloseSession(_))
        .Times(2)
        .WillOnce(Return(HDF_SUCCESS))
        .WillOnce(Return(HDF_FAILURE));
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.CloseSession(testUserId);
    service.CloseSession(testUserId);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceGetCredentialInfo001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    AuthType testAuthType = PIN;

    sptr<IdmGetCredInfoCallbackInterface> testCallback = new MockIdmGetCredentialInfoCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmGetCredentialInfoCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnCredentialInfos(_, _)).Times(2);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillOnce(Return(HDF_FAILURE));
    int32_t ret = service.GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    ret = service.GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, NOT_ENROLLED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceGetCredentialInfo002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    AuthType testAuthType = PIN;
    sptr<IdmGetCredInfoCallbackInterface> testCallback = nullptr;
    int32_t ret = service.GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceGetCredentialInfo003, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    AuthType testAuthType = PIN;
    sptr<IdmGetCredInfoCallbackInterface> testCallback = new MockIdmGetCredentialInfoCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmGetCredentialInfoCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnCredentialInfos(_, _)).Times(2);

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
    EXPECT_CALL(*mockHdi, GetUserInfo(_, _, _, _))
        .Times(2)
        .WillOnce(Return(HDF_FAILURE))
        .WillOnce(
            [](int32_t userId, uint64_t &secureUid, HdiPinSubType &pinSubType, std::vector<HdiEnrolledInfo> &infos) {
                HdiEnrolledInfo info = {
                    .enrolledId = 0,
                    .authType = static_cast<HdiAuthType>(1),
                };
                infos.push_back(info);
                pinSubType = static_cast<HdiPinSubType>(10000);
                secureUid = 4542;
                return HDF_SUCCESS;
            }
        );
    
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    int32_t ret = service.GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    ret = service.GetCredentialInfo(testUserId, testAuthType, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceGetSecInfo001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;

    sptr<IdmGetSecureUserInfoCallbackInterface> testCallback = new MockIdmGetSecureUserInfoCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmGetSecureUserInfoCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnSecureUserInfo(_)).Times(2);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetUserInfo(_, _, _, _)).WillOnce(Return(HDF_FAILURE));
    
    int32_t ret = service.GetSecInfo(testUserId, testCallback);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    ret = service.GetSecInfo(testUserId, testCallback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceGetSecInfo002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 0;
    sptr<IdmGetSecureUserInfoCallbackInterface> testCallback = nullptr;
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    int32_t ret = service.GetSecInfo(testUserId, testCallback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetUserInfo(_, _, _, _))
        .Times(2)
        .WillOnce(Return(HDF_FAILURE))
        .WillOnce(
            [](int32_t userId, uint64_t &secureUid, HdiPinSubType &pinSubType, std::vector<HdiEnrolledInfo> &infos) {
                HdiEnrolledInfo info = {
                    .enrolledId = 0,
                    .authType = static_cast<HdiAuthType>(1),
                };
                infos.push_back(info);
                pinSubType = static_cast<HdiPinSubType>(10000);
                secureUid = 4542;
                return HDF_SUCCESS;
            }
        );
    
    testCallback = new MockIdmGetSecureUserInfoCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmGetSecureUserInfoCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnSecureUserInfo(_)).Times(2);
    ret = service.GetSecInfo(testUserId, testCallback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    ret = service.GetSecInfo(testUserId, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceAddCredential001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15457;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = PIN;
    testCredPara.pinType = PIN_SIX;
    testCredPara.token = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = nullptr;
    service.AddCredential(testUserId, testCredPara, testCallback, false);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceAddCredential002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15457;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = PIN;
    testCredPara.pinType = PIN_SIX;
    testCredPara.token = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
            }
        )
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, HDF_FAILURE);
            }
        );
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginEnrollment(_, _, _, _)).WillRepeatedly(Return(HDF_FAILURE));
    
    service.AddCredential(testUserId, testCredPara, testCallback, false);
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.AddCredential(testUserId, testCredPara, testCallback, false);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceAddCredential003, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15457;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = PIN;
    testCredPara.pinType = PIN_SIX;
    testCredPara.token = {1, 2, 3, 4};
    std::shared_ptr<Context> context = nullptr;

    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .WillOnce(
            [&context](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
                if (context != nullptr) {
                    context->Stop();
                }
            }
        );
    
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, BeginEnrollment(_, _, _, _))
        .WillOnce(
            [&context](int32_t userId, const std::vector<uint8_t> &authToken, const HdiEnrollParam &param,
                HdiScheduleInfo &info) {
                HdiExecutorInfo executorInfo = {};
                executorInfo.executorIndex = 60;
                info.executors.push_back(executorInfo);
                info.scheduleId = 20;
                info.authType = HdiAuthType::PIN;
                auto contextList = ContextPool::Instance().Select(CONTEXT_ENROLL);
                if (!contextList.empty()) {
                    context = contextList[0].lock();
                }
                return HDF_SUCCESS;
            }
        );
    
    EXPECT_CALL(*mockHdi, UpdateEnrollmentResult(_, _, _)).WillOnce(Return(HDF_SUCCESS));
    std::promise<void> promise;
    EXPECT_CALL(*mockHdi, CancelEnrollment(_))
        .WillOnce(
            [&promise](int32_t userId) {
                promise.set_value();
                return HDF_SUCCESS;
            }
        );
    
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(60));
    EXPECT_CALL(*resourceNode, GetAuthType()).WillRepeatedly(Return(PIN));
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

    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.AddCredential(testUserId, testCredPara, testCallback, false);
    promise.get_future().get();

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(60));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceUpdateCredential001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 1548545;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = FACE;
    testCredPara.pinType = PIN_SIX;
    testCredPara.token = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, NOT_ENROLLED);
            }
        );
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(Return(HDF_SUCCESS));
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.UpdateCredential(testUserId, testCredPara, testCallback);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceUpdateCredential002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 1548545;
    UserIdmInterface::CredentialPara testCredPara = {};
    testCredPara.authType = FACE;
    testCredPara.pinType = PIN_SIX;
    sptr<IdmCallbackInterface> testCallback = nullptr;

    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.UpdateCredential(testUserId, testCredPara, testCallback);

    testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, GENERAL_ERROR);
            }
        )
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, HDF_FAILURE);
            }
        );
    
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _))
        .WillOnce(
            [](int32_t userId, HdiAuthType authType, std::vector<HdiCredentialInfo> &infos) {
                HdiCredentialInfo tempInfo = {
                    .credentialId = 1,
                    .executorIndex = 2,
                    .templateId = 3,
                    .authType = static_cast<HdiAuthType>(2),
                    .executorMatcher = 2,
                    .executorSensorHint = 3,
                };
                infos.push_back(tempInfo);
                return HDF_SUCCESS;
            }
        );
    
    EXPECT_CALL(*mockHdi, BeginEnrollment(_, _, _, _)).WillOnce(Return(HDF_FAILURE));

    service.UpdateCredential(testUserId, testCredPara, testCallback);

    testCredPara.token = {1, 2, 3, 4};
    service.UpdateCredential(testUserId, testCredPara, testCallback);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceCancel001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 154835;
    int32_t ret = service.Cancel(testUserId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    ret = service.Cancel(testUserId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceCancel002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 69874;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, OpenSession(_, _)).WillOnce(Return(HDF_SUCCESS));
    
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    std::vector<uint8_t> challenge;
    int32_t ret = service.OpenSession(testUserId, challenge);
    EXPECT_EQ(ret, SUCCESS);
    ret = service.Cancel(testUserId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceCancel003, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 96874;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, OpenSession(_, _)).WillOnce(Return(HDF_SUCCESS));
    
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    std::vector<uint8_t> challenge;
    int32_t ret = service.OpenSession(testUserId, challenge);
    EXPECT_EQ(ret, SUCCESS);

    auto context = Common::MakeShared<MockContext>();
    EXPECT_NE(context, nullptr);
    EXPECT_CALL(*context, GetContextType()).WillRepeatedly(Return(CONTEXT_ENROLL));
    EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(2345));
    EXPECT_CALL(*context, Stop()).WillRepeatedly(Return(true));
    EXPECT_TRUE(ContextPool::Instance().Insert(context));

    ret = service.Cancel(testUserId);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceEnforceDelUser001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15485;
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
            }
        )
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, INVALID_PARAMETERS);
            }
        );

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetUserInfo(_, _, _, _)).WillOnce(Return(HDF_FAILURE));
    
    int32_t ret = service.EnforceDelUser(testUserId, testCallback);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(ENFORCE_USER_IDM);
    ret = service.EnforceDelUser(testUserId, testCallback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceEnforceDelUser002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15485;
    sptr<IdmCallbackInterface> testCallback = nullptr;
    int32_t ret = service.EnforceDelUser(testUserId, testCallback);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceEnforceDelUser003, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15485;
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, HDF_FAILURE);
            }
        )
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
            }
        );
    
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetUserInfo(_, _, _, _))
        .WillRepeatedly(
            [](int32_t userId, uint64_t &secureUid, HdiPinSubType &pinSubType, std::vector<HdiEnrolledInfo> &infos) {
                HdiEnrolledInfo info = {
                    .enrolledId = 0,
                    .authType = static_cast<HdiAuthType>(1),
                };
                infos.push_back(info);
                pinSubType = static_cast<HdiPinSubType>(10000);
                secureUid = 4542;
                return HDF_SUCCESS;
            }
        );
    
    EXPECT_CALL(*mockHdi, EnforceDeleteUser(_, _))
        .Times(2)
        .WillOnce(Return(HDF_FAILURE))
        .WillOnce(
            [](int32_t userId, std::vector<HdiCredentialInfo> &deletedInfos) {
                HdiCredentialInfo info = {};
                info.authType = static_cast<HdiAuthType>(1);
                info.credentialId = 10;
                info.executorIndex = 20;
                info.executorMatcher = 30;
                info.executorSensorHint = 40;
                info.templateId = 50;
                deletedInfos.emplace_back(info);
                return HDF_SUCCESS;
            }
        );
    
    IpcCommon::AddPermission(ENFORCE_USER_IDM);
    int32_t ret = service.EnforceDelUser(testUserId, testCallback);
    EXPECT_EQ(ret, -1);
    ret = service.EnforceDelUser(testUserId, testCallback);
    EXPECT_EQ(ret, SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelUser001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15486465;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};

    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
            }
        )
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, HDF_FAILURE);
            }
        );
    
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteUser(_, _, _)).WillOnce(Return(HDF_FAILURE));

    service.DelUser(testUserId, testAuthToken, testCallback);
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.DelUser(testUserId, testAuthToken, testCallback);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelUser002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15486465;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = nullptr;
    service.DelUser(testUserId, testAuthToken, testCallback);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelUser003, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15486465;
    std::vector<uint8_t> testAuthToken;
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, INVALID_PARAMETERS);
            }
        );
    
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.DelUser(testUserId, testAuthToken, testCallback);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelUser004, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 15486465;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
            }
        );

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteUser(_, _, _))
        .WillOnce(
            [](int32_t userId, const std::vector<uint8_t> &authToken, std::vector<HdiCredentialInfo> &deletedInfos) {
                HdiCredentialInfo info = {};
                info.authType = static_cast<HdiAuthType>(1);
                info.credentialId = 10;
                info.executorIndex = 20;
                info.executorMatcher = 30;
                info.executorSensorHint = 40;
                info.templateId = 50;
                deletedInfos.emplace_back(info);
                return HDF_SUCCESS;
            }
        );
    
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.DelUser(testUserId, testAuthToken, testCallback);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelCredential001, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 1548865;
    uint64_t testCredentialId = 23424;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};

    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .Times(2)
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
            }
        )
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, HDF_FAILURE);
            }
        );

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteCredential(_, _, _, _)).WillOnce(Return(HDF_FAILURE));

    service.DelCredential(testUserId, testCredentialId, testAuthToken, testCallback);
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.DelCredential(testUserId, testCredentialId, testAuthToken, testCallback);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelCredential002, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 1548865;
    uint64_t testCredentialId = 23424;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    sptr<IdmCallbackInterface> testCallback = nullptr;
    service.DelCredential(testUserId, testCredentialId, testAuthToken, testCallback);
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceDelCredential003, TestSize.Level0)
{
    UserIdmService service(123123, true);
    int32_t testUserId = 1548865;
    uint64_t testCredentialId = 23424;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};

    sptr<IdmCallbackInterface> testCallback = new MockIdmCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockIdmCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _))
        .WillOnce(
            [](int32_t result, const Attributes &extraInfo) {
                EXPECT_EQ(result, SUCCESS);
            }
        );

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, DeleteCredential(_, _, _, _))
        .WillOnce(
            [](int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, HdiCredentialInfo &info) {
                info.authType = static_cast<HdiAuthType>(1);
                info.credentialId = 10;
                info.executorIndex = 20;
                info.executorMatcher = 30;
                info.executorSensorHint = 40;
                info.templateId = 50;
                return HDF_SUCCESS;
            }
        );
    
    IpcCommon::AddPermission(MANAGE_USER_IDM_PERMISSION);
    service.DelCredential(testUserId, testCredentialId, testAuthToken, testCallback);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserIdmServiceTest, UserIdmServiceTestDump, TestSize.Level0)
{
    int testFd1 = -1;
    int testFd2 = 1;
    std::vector<std::u16string> testArgs;

    UserIdmService service(123123, true);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetUserInfo(_, _, _, _))
        .Times(2)
        .WillOnce(Return(HDF_FAILURE))
        .WillOnce(
            [](int32_t userId, uint64_t &secureUid, HdiPinSubType &pinSubType, std::vector<HdiEnrolledInfo> &infos) {
                HdiEnrolledInfo info = {
                    .enrolledId = 0,
                    .authType = static_cast<HdiAuthType>(1),
                };
                infos.push_back(info);
                pinSubType = static_cast<HdiPinSubType>(10000);
                secureUid = 4542;
                return HDF_SUCCESS;
            }
        );

    EXPECT_EQ(service.Dump(testFd1, testArgs), INVALID_PARAMETERS);
    EXPECT_EQ(service.Dump(testFd2, testArgs), SUCCESS);
    testArgs.push_back(u"-h");
    EXPECT_EQ(service.Dump(testFd2, testArgs), SUCCESS);
    testArgs.clear();
    testArgs.push_back(u"-l");
    EXPECT_EQ(service.Dump(testFd2, testArgs), SUCCESS);
    EXPECT_EQ(service.Dump(testFd2, testArgs), SUCCESS);
    testArgs.clear();
    testArgs.push_back(u"-k");
    EXPECT_EQ(service.Dump(testFd2, testArgs), GENERAL_ERROR);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS