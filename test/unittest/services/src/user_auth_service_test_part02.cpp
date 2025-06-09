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
#include "mock_event_listener.h"
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

static void InitIpcAuthParamInner(IpcAuthParamInner &authParam,
    std::vector<uint8_t> &challenge, std::vector<int32_t> &authTypes, int32_t authTrustLevel)
{
    authParam.challenge = challenge;
    authParam.authTypes = authTypes;
    authParam.authTrustLevel = authTrustLevel;
}

static void InitIpcWidgetParamInner(IpcWidgetParamInner &widgetParam,
    const std::string &title, const std::string &navigationButtonText, int32_t windowMode)
{
    widgetParam.title = title;
    widgetParam.navigationButtonText = navigationButtonText;
    widgetParam.windowMode = windowMode;
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "确定", 0);
    sptr<IIamCallback> testUserAuthCallback(nullptr);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testUserAuthCallback, testModalCallback,
        contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, (uint64_t)0);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_002, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_003, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_004, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(USE_USER_IDM_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_005, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_006, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_007, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes;
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(2);
    int32_t userId = 1;
    IpcCommon::GetCallingUserId(service, userId);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);

    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(FACE);
    ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_008, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {5};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_009, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {ALL};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_010, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, 50000);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TRUST_LEVEL_NOT_SUPPORT);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_011, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL1);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_012, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL1);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "WidgetParamTitle", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<MockUserAuthCallback> testCallback(new (std::nothrow) MockUserAuthCallback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<IIamCallback> callbackInterface = testCallback;
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, callbackInterface, testModalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_013, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillRepeatedly(Return(FAIL));
    sptr<IModalCallback> modalCallback = new MockModalCallback();
    EXPECT_NE(modalCallback, nullptr);
    auto *testModalCallback = static_cast<MockModalCallback *>(modalCallback.GetRefPtr());
    EXPECT_NE(testModalCallback, nullptr);
    EXPECT_CALL(*testModalCallback, SendCommand(_, _)).Times(0);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, modalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_014, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, 50000);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);
    EXPECT_CALL(*tempCallback, OnResult(_, _)).Times(1);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback,
        contextId);
    EXPECT_EQ(ret, TRUST_LEVEL_NOT_SUPPORT);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_015, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback,
        contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_016, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
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
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault([](const Attributes &condition, Attributes &values) {
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0017, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    auto *tempCallback = static_cast<MockUserAuthCallback *>(testCallback.GetRefPtr());
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
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(0));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ON_CALL(*resourceNode1, GetProperty).WillByDefault([](const Attributes &condition, Attributes &values) {
            values.SetStringValue(Attributes::ATTR_PIN_SUB_TYPE, "test");
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0018, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    ON_CALL(*resourceNode1, GetProperty).WillByDefault([acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0019, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    ON_CALL(*resourceNode1, GetProperty).WillByDefault([acquire](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, acquire);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, acquire);
            return SUCCESS;
        }
    );
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, FAIL);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    service.CancelAuthOrIdentify(contextId, 0);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0020, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_0021, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {ALL};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_022, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_NE(contextId, INVALID_CONTEXT_ID);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(0));
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_023, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    authParam.reuseUnlockResult.isReuse = true;
    authParam.reuseUnlockResult.reuseMode = AUTH_TYPE_IRRELEVANT;
    authParam.reuseUnlockResult.reuseDuration = 5 * 60 *1000;
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(contextId, REUSE_AUTH_RESULT_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_024, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "确定", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_025, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "确定", WindowModeType::UNKNOWN_WINDOW_MODE);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_026, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_027, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_028, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_029, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    authParam.isUserIdSpecified = true;
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, GENERAL_ERROR);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_030, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    authParam.isUserIdSpecified = true;
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
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
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_031, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FACE, FINGERPRINT};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_032, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT, FACE};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "", WindowModeType::FULLSCREEN);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceAuthWidget_033, TestSize.Level0)
{
    UserAuthService service;
    int32_t apiVersion = 10;
    std::vector<uint8_t> challenge = {1};
    std::vector<int32_t> authTypes = {FINGERPRINT, FACE, PRIVATE_PIN};
    IpcAuthParamInner authParam;
    InitIpcAuthParamInner(authParam, challenge, authTypes, ATL2);
    IpcWidgetParamInner widgetParam;
    InitIpcWidgetParamInner(widgetParam, "使用密码验证", "test", WindowModeType::DIALOG_BOX);
    sptr<IIamCallback> testCallback = new MockUserAuthCallback();
    EXPECT_NE(testCallback, nullptr);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetAvailableStatus(_, _, _, _)).Times(0);
    EXPECT_CALL(*mockHdi, BeginAuthentication(_, _, _)).Times(0);
    sptr<IModalCallback> testModalCallback(nullptr);
    uint64_t contextId = 0;
    int32_t ret = service.AuthWidget(apiVersion, authParam, widgetParam, testCallback, testModalCallback, contextId);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    EXPECT_EQ(contextId, BAD_CONTEXT_ID);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {PIN, FACE, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    const WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::NONE_INTERRUPTION_DIALOG_BOX,
    };
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {PIN, FACE, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    const WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .challenge = challenge,
        .authTypes = {PIN, FACE, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    const WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthPermissionAndParam_004, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const AuthParamInner authParam = {
        .userId = 200,
        .challenge = challenge,
        .authTypes = {PIN, FACE, PRIVATE_PIN},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    const WidgetParamInner widgetParam = {
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t ret = service.CheckAuthPermissionAndParam(authParam, widgetParam, true);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    const WidgetParamInner widgetParam = {
        .title = "使用密码验证",
        .navigationButtonText = "navigationButtonText",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    IpcCommon::AddPermission(ACCESS_BIOMETRIC_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(USER_AUTH_FROM_BACKGROUND);
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    int32_t userId = 100;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(FACE);
    authTypeList.push_back(ALL);
    authTypeList.push_back(PIN);
    authTypeList.push_back(FINGERPRINT);
    AuthTrustLevel atl = ATL3;
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = authTypeList,
        .authTrustLevel = atl,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillOnce(Return(HDF_SUCCESS));
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::FACE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), false);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::PRIVATE_PIN);
    validAuthTypeList.push_back(AuthType::FACE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::FINGERPRINT);
    authTypeList.push_back(AuthType::FACE);
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::PRIVATE_PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_001, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t ret = service.Notice(static_cast<int32_t>(NoticeType::WIDGET_NOTICE), "PIN");
    EXPECT_NE(ret, ResultCode::SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_002, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    int32_t ret = service.Notice(static_cast<int32_t>(NoticeType::WIDGET_NOTICE), "PIN");
    EXPECT_EQ(ret, ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceNotice_003, TestSize.Level0)
{
    UserAuthService service;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    int32_t ret = service.Notice(static_cast<int32_t>(NoticeType::WIDGET_NOTICE), "PIN");
    EXPECT_EQ(ret, ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_SYSTEM_APP_FAILED);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_002, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(2, testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_005, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = new MockIWidgetCallback();
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    IpcCommon::AddPermission(SUPPORT_USER_AUTH);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegisterWidgetCallback_006, TestSize.Level0)
{
    UserAuthService service;
    sptr<IWidgetCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegisterWidgetCallback(1, testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback),
        ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback),
        ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceRegistEventListerner_005, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback),
        ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_001, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = nullptr;
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::INVALID_PARAMETERS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_002, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_003, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceUnRegistEventListerner_004, TestSize.Level0)
{
    UserAuthService service;
    sptr<IEventListenerCallback> testCallback = new MockEventListener();
    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    EXPECT_EQ(service.RegistUserAuthSuccessEventListener(testCallback), ResultCode::GENERAL_ERROR);
    EXPECT_EQ(service.UnRegistUserAuthSuccessEventListener(testCallback), ResultCode::GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceSetGlobalConfigParam001, TestSize.Level0)
{
    UserAuthService service;
    IpcGlobalConfigParam param = {};
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
    IpcGlobalConfigParam param = {};
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
    IpcGlobalConfigParam param = {};
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
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
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
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface), INVALID_PARAMETERS);

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
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface);

    IpcCommon::AddPermission(USE_USER_ACCESS_MANAGER);
    EXPECT_EQ(service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface), CHECK_SYSTEM_APP_FAILED);
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
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface), HDF_FAILURE);
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
    sptr<IVerifyTokenCallback> callbackInterface = testCallback;
    EXPECT_EQ(service.VerifyAuthToken(testTokenIn, allowableDuration, callbackInterface), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _))
        .WillOnce([](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
            static const uint32_t USER_AUTH_TOKEN_LEN = 148;
            reuseInfo.token.resize(USER_AUTH_TOKEN_LEN);
            return HDF_SUCCESS;
        });

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> extraInfo;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, extraInfo), SUCCESS);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _))
        .WillOnce([](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
            static const uint32_t USER_AUTH_TOKEN_LEN = 148;
            reuseInfo.token.resize(USER_AUTH_TOKEN_LEN);
            return HDF_SUCCESS;
        });

    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> extraInfo;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, extraInfo), CHECK_PERMISSION_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult003, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _))
        .WillOnce([](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
            static const uint32_t USER_AUTH_TOKEN_LEN = 148;
            reuseInfo.token.resize(USER_AUTH_TOKEN_LEN);
            return HDF_SUCCESS;
        });

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    std::vector<uint8_t> extraInfo;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, extraInfo), CHECK_SYSTEM_APP_FAILED);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult004, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _))
        .WillOnce([](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
            return HDF_FAILURE;
        });

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> extraInfo;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, extraInfo), HDF_FAILURE);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult005, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> extraInfo;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, extraInfo), GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(UserAuthServiceTest, QueryReusableAuthResult006, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> tempChallenge = {};
    tempChallenge.resize(32);
    IpcAuthParamInner ipcAuthParamInner = {};
    ipcAuthParamInner.userId = 1;
    ipcAuthParamInner.isUserIdSpecified = true;
    ipcAuthParamInner.challenge = tempChallenge;
    ipcAuthParamInner.authTrustLevel = ATL3;
    ipcAuthParamInner.authTypes.push_back(PIN);
    ipcAuthParamInner.reuseUnlockResult.isReuse = true;
    ipcAuthParamInner.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;
    ipcAuthParamInner.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _))
        .WillOnce([](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
            return HDF_SUCCESS;
        });

    IpcCommon::AddPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    IpcCommon::AddPermission(IS_SYSTEM_APP);
    std::vector<uint8_t> extraInfo;
    EXPECT_EQ(service.QueryReusableAuthResult(ipcAuthParamInner, extraInfo), GENERAL_ERROR);
    IpcCommon::DeleteAllPermission();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS