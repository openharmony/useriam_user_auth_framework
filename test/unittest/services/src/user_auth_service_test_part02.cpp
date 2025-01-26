/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
#include "mock_auth_event_listener.h"
#include "mock_context.h"
#include "mock_iuser_auth_interface.h"
#include "mock_ipc_common.h"
#include "mock_modal_callback.h"
#include "mock_user_access_ctrl_callback.h"
#include "mock_user_auth_callback.h"
#include "mock_user_auth_service.h"
#include "mock_resource_node.h"
#include "mock_widget_callback_interface.h"
#include "resource_node_pool.h"
#include "user_auth_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";

    sptr<UserAuthCallbackInterface> testUserAuthCallback(nullptr);
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    EXPECT_EQ(service.AuthWidget(apiVersion, authParam, widgetParam, testUserAuthCallback, testModalCallback),
        (uint64_t)0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_002, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_003, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_004, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_005, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    service.CancelAuthOrIdentify(conxtId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_006, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    service.CancelAuthOrIdentify(conxtId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_007, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(2);
    int32_t userId = 1;
    IpcCommon::GetCallingUserId(service, userId);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);

    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_008, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(static_cast<AuthType>(5));
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_009, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(AuthType::ALL);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_010, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(AuthType::PIN);
    authParam.authTrustLevel = (AuthTrustLevel)50000;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_011, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(AuthType::PIN);
    authParam.authTrustLevel = ATL1;
    WidgetParamInner widgetParam;
    widgetParam.title = "";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_012, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(AuthType::PIN);
    authParam.authTrustLevel = ATL1;
    WidgetParamInner widgetParam;
    widgetParam.title = "WidgetParamTitle";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<UserAuthCallbackInterface> callbackInterface = testCallback;
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    service.CancelAuthOrIdentify(conxtId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_013, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<ModalCallbackInterface> modalCallback = new MockModalCallback();
    EXPECT_NE(modalCallback, nullptr);
    auto *testModalCallback = static_cast<MockModalCallback *>(modalCallback.GetRefPtr());
    EXPECT_NE(testModalCallback, nullptr);
    EXPECT_CALL(*testModalCallback, SendCommand(_, _)).Times(0);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, modalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_014, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(FACE);
    authParam.authTrustLevel = (AuthTrustLevel)50000;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_015, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.challenge.push_back(2);
    authParam.challenge.push_back(3);
    authParam.challenge.push_back(4);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
                .executorMatcher = 2,
                .executorSensorHint = 3,
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    ResourceNodePool::Instance().Insert(nullptr);
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    service.CancelAuthOrIdentify(conxtId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_016, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::PIN);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
                .executorMatcher = 2,
                .executorSensorHint = 3,
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            return SUCCESS;
        }
    );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(conxtId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0017, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
                .executorMatcher = 2,
                .executorSensorHint = 3,
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetStringValue(Attributes::ATTR_PIN_SUB_TYPE, "test");
            return SUCCESS;
        }
    );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(conxtId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0018, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            return SUCCESS;
        }
    );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(conxtId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0019, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            return SUCCESS;
        }
    );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(conxtId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0020, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::PIN);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(0),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, acquire);
            return SUCCESS;
        }
    );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0021, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::ALL);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(0),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, acquire);
            return SUCCESS;
        }
    );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_022, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    int32_t acquire = 20;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    ON_CALL(*mockHdi, GetCredential).WillByDefault(
        [](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo tempInfo = {
                .credentialId = 1,
                .executorIndex = 0,
                .templateId = 3,
                .authType = static_cast<HdiAuthType>(1),
            };
            infos.push_back(tempInfo);
            return HDF_SUCCESS;
        }
    );
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault(
        [acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, acquire);
            return SUCCESS;
        }
    );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t conxtId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_NE(conxtId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_023, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    authParam.reuseUnlockResult.isReuse = true;
    authParam.reuseUnlockResult.reuseMode = AUTH_TYPE_IRRELEVANT;
    authParam.reuseUnlockResult.reuseDuration = 5 * 60 *1000;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _)).Times(1);
    ON_CALL(*mockHdi, CheckReuseUnlockResult)
        .WillByDefault(
            [](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
                static const uint32_t USER_AUTH_TOKEN_LEN = 148;
                reuseInfo.token.resize(USER_AUTH_TOKEN_LEN);
                return HDF_SUCCESS;
            }
        );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, REUSE_AUTH_RESULT_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_024, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_025, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                return PIN_EXPIRED;
            }
        );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_026, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::FACE);
                return HDF_SUCCESS;
            }
        );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_027, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::FINGERPRINT);
                return HDF_SUCCESS;
            }
        );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_028, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::PIN);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::PIN);
                return HDF_SUCCESS;
            }
        );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_029, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::PIN);
    authParam.authTrustLevel = ATL2;
    authParam.isUserIdSpecified = true;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::PIN);
                return HDF_SUCCESS;
            }
        );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_030, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::PIN);
    authParam.authTrustLevel = ATL2;
    authParam.isUserIdSpecified = true;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    ON_CALL(*mockHdi, GetValidSolution)
        .WillByDefault(
            [](int32_t userId, const std::vector<int32_t>& authTypes, uint32_t authTrustLevel,
            std::vector<int32_t>& validTypes) {
                validTypes.clear();
                validTypes.push_back(AuthType::PIN);
                return HDF_SUCCESS;
            }
        );
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_031, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FACE);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_032, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    AuthParamInner authParam;
    authParam.challenge.push_back(1);
    authParam.authTypes.push_back(AuthType::FINGERPRINT);
    authParam.authTypes.push_back(AuthType::FACE);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "";
    widgetParam.windowMode = WindowModeType::FULLSCREEN;
    sptr<UserAuthCallbackInterface> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    sptr<ModalCallbackInterface> testModalCallback(nullptr);
    uint64_t contextId = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}
HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_001, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t ret = service.Notice(NoticeType::WIDGET_NOTICE, "PIN");
    EXPECT_NE(ret, ResultCode::SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_002, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    int32_t ret = service.Notice(NoticeType::WIDGET_NOTICE, "PIN");
    EXPECT_EQ(ret, ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_003, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t ret = service.Notice(NoticeType::WIDGET_NOTICE, "PIN");
    EXPECT_EQ(ret, ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_002, TestSize.Level0)
{
    UserAuthService service;
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(2, testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_005, TestSize.Level0)
{
    UserAuthService service;
    sptr<WidgetCallbackInterface> testCallback = new MockWidgetCallbackInterface();
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_006, TestSize.Level0)
{
    UserAuthService service;
    sptr<WidgetCallbackInterface> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = nullptr;
    std::vector<AuthType> authTypeList;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(authTypeList, testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_002, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    std::vector<AuthType> authTypeList;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(authTypeList, testCallback),
        ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(authTypeList, testCallback),
        ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(authTypeList, testCallback), ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_005, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::ALL);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(authTypeList, testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_002, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<AuthEventListenerInterface> testCallback = new MockAuthEventListener();
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PIN);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::FINGERPRINT);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(authTypeList, testCallback), ResultCode::GENERAL_ERROR);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam001, TestSize.Level0)
{
    UserAuthService service;
    GlobalConfigParam param = {};
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = PIN_EXPIRED_PERIOD;
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);
    param.authTypes.push_back(PIN);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::SUCCESS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(*mockHdi, SetGlobalConfigParam)
        .WillByDefault(
            [](const HdiGlobalConfigParam &param) {
                return HDF_SUCCESS;
            }
        );
    EXPECT_EQ(service.SetGlobalConfigParam(param), HDF_SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam002, TestSize.Level0)
{
    UserAuthService service;
    GlobalConfigParam param = {};
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::CHECK_PERMISSION_FAILED);

    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = ENABLE_STATUS;
    param.value.enableStatus = true;
    param.userIds.push_back(1);
    param.authTypes.push_back(PIN);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::SUCCESS);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, SetGlobalConfigParam(_)).Times(1);
    ON_CALL(*mockHdi, SetGlobalConfigParam)
        .WillByDefault(
            [](const HdiGlobalConfigParam &param) {
                return HDF_FAILURE;
            }
        );
    EXPECT_EQ(service.SetGlobalConfigParam(param), HDF_FAILURE);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam003, TestSize.Level0)
{
    UserAuthService service;
    GlobalConfigParam param = {};
    IpcCommon::AddPermission(ENTERPRISE_DEVICE_MGR);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);

    param.type = PIN_EXPIRED_PERIOD;
    param.value.enableStatus = true;
    param.userIds.push_back(1);
    param.authTypes.push_back(ALL);
    param.authTypes.push_back(PIN);
    param.authTypes.push_back(FACE);
    param.authTypes.push_back(FINGERPRINT);
    param.authTypes.push_back(RECOVERY_KEY);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);
    param.authTypes.clear();
    param.authTypes.push_back(FACE);
    EXPECT_EQ(service.SetGlobalConfigParam(param), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    testTokenIn.resize(1);
    uint64_t allowableDuration = 0;

    sptr<MockVerifyTokenCallback> testCallback(nullptr);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, VerifyAuthToken(_, _, _, _))
        .WillOnce([](const std::vector<uint8_t>& tokenIn, uint64_t allowableDuration,
            HdiUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t>& rootSecret) {
            return HDF_SUCCESS;
        });

    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<VerifyTokenCallbackInterface> callbackInterface = testCallback;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    uint64_t allowableDuration = 0;
    sptr<MockVerifyTokenCallback> testCallback(nullptr);
    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(2);
    sptr<VerifyTokenCallbackInterface> callbackInterface = testCallback;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);

    testTokenIn.resize(1);
    allowableDuration = 25 * 60 * 60 * 1000;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    testTokenIn.resize(1);
    uint64_t allowableDuration = 0;
    sptr<MockVerifyTokenCallback> testCallback(nullptr);
    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(2);
    sptr<VerifyTokenCallbackInterface> callbackInterface = testCallback;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);

    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken004, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    testTokenIn.resize(1);
    uint64_t allowableDuration = 0;

    sptr<MockVerifyTokenCallback> testCallback(nullptr);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, VerifyAuthToken(_, _, _, _))
        .WillOnce([](const std::vector<uint8_t>& tokenIn, uint64_t allowableDuration,
            HdiUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t>& rootSecret) {
            return HDF_FAILURE;
        });

    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<VerifyTokenCallbackInterface> callbackInterface = testCallback;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceVerifyAuthToken005, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> testTokenIn = {};
    testTokenIn.resize(1);
    uint64_t allowableDuration = 0;

    sptr<MockVerifyTokenCallback> testCallback(nullptr);

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, VerifyAuthToken(_, _, _, _))
        .WillOnce([](const std::vector<uint8_t>& tokenIn, uint64_t allowableDuration,
            HdiUserAuthTokenPlain &tokenPlainOut, std::vector<uint8_t>& rootSecret) {
            rootSecret.push_back(1);
            return HDF_SUCCESS;
        });

    testCallback = sptr<MockVerifyTokenCallback>(new (std::nothrow) MockVerifyTokenCallback());
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnVerifyTokenResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<VerifyTokenCallbackInterface> callbackInterface = testCallback;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);
    IpcCommon::DeleteAllPermission();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS