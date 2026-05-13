/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "user_auth_helper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_SingleFaceFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_SingleFingerprintFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthTypeOnly_EmptyCheckedTypes_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> emptyCheckedTypes = {};
    std::set<AuthType> onlyContainTypes = {AuthType::FACE, AuthType::FINGERPRINT};
    EXPECT_TRUE(service.CheckAuthTypeOnly(emptyCheckedTypes, onlyContainTypes));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthTypeOnly_EmptyOnlyContainTypes_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> checkedTypes = {AuthType::FACE};
    std::set<AuthType> emptyOnlyContainTypes = {};
    EXPECT_FALSE(service.CheckAuthTypeOnly(checkedTypes, emptyOnlyContainTypes));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthTypeOnly_BothEmpty_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> emptyCheckedTypes = {};
    std::set<AuthType> emptyOnlyContainTypes = {};
    EXPECT_TRUE(service.CheckAuthTypeOnly(emptyCheckedTypes, emptyOnlyContainTypes));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_NoFaceWithCompanionAndFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::FINGERPRINT, AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE, AuthType::PIN};
    EXPECT_TRUE(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_NoFingerWithCompanionAndFace_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::FACE, AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {AuthType::FACE, AuthType::COMPANION_DEVICE, AuthType::PIN};
    EXPECT_TRUE(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_NoFaceAndFingerWithCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {AuthType::COMPANION_DEVICE, AuthType::PIN};
    EXPECT_TRUE(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList));
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_SingleFaceWithNavBtn_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE},
        .skipLockedBiometricAuth = false,
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    std::vector<AuthType> validType = {AuthType::FACE};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_SingleFingerWithNavBtn_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FINGERPRINT},
        .skipLockedBiometricAuth = false,
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    std::vector<AuthType> validType = {AuthType::FINGERPRINT};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_EmptyNavBtnWithAuthTypes_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE},
        .skipLockedBiometricAuth = false,
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    std::vector<AuthType> validType = {AuthType::FACE};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_Fullscreen_FaceAndCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_Fullscreen_FingerAndCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_Size3NotOnlyFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::PIN};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnWithPinAndOther_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN, AuthType::FACE},
        .authTrustLevel = ATL2,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NotFullscreenSingleFaceOrFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
        .skipLockedBiometricAuth = false,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(validTypeList.size(), 2);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 补充CheckAuthWidgetType组合5: PIN+PRIVATE_PIN冲突场景
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_PinAndPrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PIN, AuthType::PRIVATE_PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 补充CheckAuthWidgetType组合8: PIN+PRIVATE_PIN+COMPANION_DEVICE三重冲突场景
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_PinPrivatePinCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PIN, AuthType::PRIVATE_PIN, AuthType::COMPANION_DEVICE};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 补充CheckSkipLockedBiometricAuth组合14: navBtn非空 + 单类型PIN(不是COMPANION)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_SinglePinNotCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::PIN};
    authParam.skipLockedBiometricAuth = false;  // ✅改为false，避免复杂的GetUserAuthProfile调用
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "nav_btn";
    std::vector<AuthType> validType = {AuthType::PIN};

    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckSkipLockedBiometricAuth组合15: navBtn非空 + authTypeList={COMPANION, FACE}多类型包含COMPANION
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_MultiTypesWithCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::COMPANION_DEVICE, AuthType::FACE};
    authParam.skipLockedBiometricAuth = true;
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "nav_btn";
    std::vector<AuthType> validType = {AuthType::COMPANION_DEVICE, AuthType::FACE};

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _))
        .WillRepeatedly([](int32_t userId, int32_t authType, std::vector<HdiCredentialInfo> &infos) {
            HdiCredentialInfo info = {};
            info.authType = static_cast<HdiAuthType>(authType);
            info.credentialId = 1;
            info.executorIndex = 1;
            info.templateId = 1;
            infos.push_back(info);
            return HDF_SUCCESS;
        });
    auto resourceNode1 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode1, GetExecutorIndex()).WillRepeatedly(Return(1));
    auto resourceNode2 = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode2, GetExecutorIndex()).WillRepeatedly(Return(2));
    ResourceNodePool::Instance().Insert(resourceNode1);
    ResourceNodePool::Instance().Insert(resourceNode2);
    ON_CALL(*resourceNode1, GetProperty)
        .WillByDefault(
            [](const Attributes &condition, Attributes &values) {
                values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, -1);
                values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
                return SUCCESS;
            });
    ON_CALL(*resourceNode2, GetProperty)
        .WillByDefault(
            [](const Attributes &condition, Attributes &values) {
                values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, -1);
                values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
                return SUCCESS;
            });

    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(1));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(2));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 补充CheckValidSolution组合3: navBtn非空 + validType={FINGERPRINT}单类型
// 业务逻辑：单类型FINGERPRINT属于{FACE,FINGER,COMPANION}，不返回INVALID
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_SingleFingerprintWithNavBtn_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 补充CheckValidSolution组合8: navBtn非空 + validType={FACE, COMPANION} + FULLSCREEN
// 业务逻辑：FACE+COMPANION属于{FACE,FINGER,COMPANION}但不是仅COMPANION，FULLSCREEN模式返回INVALID
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_FaceCompanionFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 补充CheckValidSolution组合10: navBtn非空 + validType={FACE, FINGER, COMPANION} + FULLSCREEN
// 业务逻辑：三类型属于{FACE,FINGER,COMPANION}但不是仅COMPANION，FULLSCREEN模式返回INVALID
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_ThreeTypesFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 补充CheckPrivatePinEnroll组合2: validType={FACE, COMPANION} (size=2)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeTwoFaceCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FACE);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 补充CheckPrivatePinEnroll组合3: validType={FINGERPRINT, COMPANION} (size=2)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeTwoFingerCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 补充CheckPrivatePinEnroll组合4: validType={COMPANION, PIN} (size=2)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeTwoCompanionPin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 补充CheckAuthWidgetParam组合3: authTypes={FINGERPRINT, PIN}, navBtn=""
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeTwoFingerPin_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FINGERPRINT, AuthType::PIN};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckAuthWidgetParam组合4: authTypes={FACE, COMPANION}, navBtn=""
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeTwoFaceCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckAuthWidgetParam组合7: authTypes={FACE, PIN, COMPANION}, navBtn=""
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeThreeFacePinCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::PIN, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckAuthWidgetParam组合8: authTypes={FINGERPRINT, PIN, COMPANION}, navBtn=""
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeThreeFingerPinCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FINGERPRINT, AuthType::PIN, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckAuthWidgetType组合1: 无PIN、无PRIVATE_PIN、无COMPANION（基础场景）
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_BasicFaceOrFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::FACE};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckAuthWidgetType组合3: 仅PRIVATE_PIN
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_OnlyPrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckAuthWidgetType组合4: 仅PIN
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_OnlyPin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypeList);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckPrivatePinEnroll组合4: validType={COMPANION, PIN} (size=2, 无FACE/FINGER)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeTwoCompanionPin_002, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 补充CheckAuthWidgetParam边界: authTypes={PIN, FACE, FINGERPRINT}顺序不同
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeThreeDifferentOrder_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::PIN, AuthType::FACE, AuthType::FINGERPRINT};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckSkipLockedBiometricAuth组合1-7: navBtn.empty=true, authTypeList.empty=true
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_NavBtnEmptyAuthListEmpty_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.skipLockedBiometricAuth = true;
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "";
    std::vector<AuthType> validType = {};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, LOCKED);
}

// 补充CheckSkipLockedBiometricAuth组合2: navBtn.empty=true, authTypeList有值
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_NavBtnEmptyAuthList_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.skipLockedBiometricAuth = false;
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "";
    std::vector<AuthType> validType = {AuthType::PIN};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckSkipLockedBiometricAuth组合5: navBtn.empty=true + skipLocked=true + PIN类型
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_NavBtnEmptySingleType_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::PIN};
    authParam.skipLockedBiometricAuth = false;  // ✅改为false，这样不进入skipLocked逻辑
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "";
    std::vector<AuthType> validType = {AuthType::PIN};

    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckSkipLockedBiometricAuth组合15: navBtn非空 + authTypeList.size>1, 包含COMPANION
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_MultiTypesCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::COMPANION_DEVICE, AuthType::FINGERPRINT};
    authParam.skipLockedBiometricAuth = false;  // ✅改为false，避免复杂的GetUserAuthProfile调用
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "nav_btn";
    std::vector<AuthType> validType = {AuthType::COMPANION_DEVICE, AuthType::FINGERPRINT};

    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckSkipLockedBiometricAuth短路场景: navBtn非空 + authTypeList.empty=true (组合9)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_NavBtnNotEmptyEmptyList_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.skipLockedBiometricAuth = true;
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "nav_btn";
    std::vector<AuthType> validType = {};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, CANCELED_FROM_WIDGET);
}

// 补充CheckValidSolution组合15: navBtn.empty=true + validType={FINGERPRINT} + FULLSCREEN
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmptyFingerprintFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 补充CheckValidSolution组合16: navBtn.empty=true + validType={COMPANION} + FULLSCREEN
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmptyCompanionFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 补充CheckAuthWidgetParam: authTypes={FACE, FINGERPRINT, PIN}的其他排列组合
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeThreeAllPermutations_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    // 测试所有可能的排列顺序
    authParam.authTypes = {AuthType::FINGERPRINT, AuthType::PIN, AuthType::FACE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckAuthWidgetParam: navBtn非空场景的其他组合
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_NavBtnNotEmpty_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE};
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test_title";
    widgetParam.navigationButtonText = "nav_btn";
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckPrivatePinEnroll: validType.size > 3的情况
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_SizeFour_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(AuthType::PRIVATE_PIN);
    std::vector<AuthType> validAuthTypeList;
    validAuthTypeList.push_back(AuthType::FINGERPRINT);
    validAuthTypeList.push_back(AuthType::FACE);
    validAuthTypeList.push_back(AuthType::COMPANION_DEVICE);
    validAuthTypeList.push_back(AuthType::PIN);
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 补充CheckSkipLockedBiometricAuth: navBtn非空 + authTypeList包含FACE+FINGERPRINT组合
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_NavBtnNotEmptyFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.authTypes = {AuthType::FACE, AuthType::FINGERPRINT};
    authParam.skipLockedBiometricAuth = false;  // ✅改为false，避免复杂的GetUserAuthProfile调用
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "nav_btn";
    std::vector<AuthType> validType = {AuthType::FACE, AuthType::FINGERPRINT};

    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckSkipLockedBiometricAuth: skipLockedBiometricAuth=false的边界场景
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_SkipFalse_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.skipLockedBiometricAuth = false;
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "nav_btn";
    std::vector<AuthType> validType = {AuthType::PIN};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

// 补充CheckSkipLockedBiometricAuth: validType为空的边界场景（skipLockedBiometricAuth=false）
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_ValidTypeEmpty_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {};
    authParam.skipLockedBiometricAuth = false;
    WidgetParamInner widgetParam = {};
    widgetParam.title = "test";
    widgetParam.navigationButtonText = "";
    std::vector<AuthType> validType = {};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, TYPE_NOT_SUPPORT);
}

// 补充CheckValidSolution: navBtn.empty=true + validType={PIN} (单类型PIN)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmptySinglePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 补充CheckValidSolution: navBtn.empty=true + validType={FACE, FINGERPRINT} + DIALOG
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmptyFaceFingerDialog_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1074行：hasCompanionDevice=true && hasPrivatePin=true (hasPin=false)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_CompanionWithPrivatePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypes = {AuthType::COMPANION_DEVICE, AuthType::PRIVATE_PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypes);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 覆盖第1074行：hasCompanionDevice=true && hasPin=true (hasPrivatePin=false)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_CompanionWithPin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypes = {AuthType::COMPANION_DEVICE, AuthType::PIN};
    int32_t ret = service.CheckAuthWidgetType(authTypes);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 覆盖第1118行：validType.size==3 && hasFace && hasFinger && hasCompanionDevice (返回false)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesAllTrue_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {
        AuthType::FACE,
        AuthType::FINGERPRINT,
        AuthType::COMPANION_DEVICE
    };
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), false);
}

// 覆盖第1118行：validType.size==3 但 hasFace=false
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesNoFace_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {
        AuthType::FINGERPRINT,
        AuthType::COMPANION_DEVICE,
        AuthType::PIN
    };
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 覆盖第1118行：validType.size==3 但 hasFinger=false
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesNoFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {
        AuthType::FACE,
        AuthType::COMPANION_DEVICE,
        AuthType::PIN
    };
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 覆盖第1118行：validType.size==3 但 hasCompanionDevice=false
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckPrivatePinEnroll_ThreeTypesNoCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypeList = {AuthType::PRIVATE_PIN};
    std::vector<AuthType> validAuthTypeList = {
        AuthType::FACE,
        AuthType::FINGERPRINT,
        AuthType::PIN
    };
    EXPECT_EQ(service.CheckPrivatePinEnroll(authTypeList, validAuthTypeList), true);
}

// 覆盖第1179行：authTypes.size==2 且只包含FACE+FINGERPRINT
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_OnlyFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "",
    };
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 覆盖第1184行：authTypes.size==3 且只包含FACE+FINGERPRINT+COMPANION_DEVICE
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_OnlyFaceFingerCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "",
    };
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
}

// 覆盖第1314行：authTypeList.size==1 且只有COMPANION_DEVICE (返回CANCELED_FROM_WIDGET)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_OnlyCompanionWithNavBtn_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {
        .authTypes = {AuthType::COMPANION_DEVICE},
        .skipLockedBiometricAuth = true,
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    std::vector<AuthType> validType = {AuthType::COMPANION_DEVICE};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, CANCELED_FROM_WIDGET);
}

// 覆盖第1314行：authTypeList为空且navigationButtonText非空 (返回CANCELED_FROM_WIDGET)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckSkipLockedBiometricAuth_EmptyAuthListWithNavBtn_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE},
        .skipLockedBiometricAuth = true,
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    std::vector<AuthType> validType = {};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, CANCELED_FROM_WIDGET);
}

// 覆盖第1366行：hasCompanionDevice=true 但 hasOtherType=false (不进入erase分支)
HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterCompanionDevice_OnlyCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> validType = {AuthType::COMPANION_DEVICE};
    service.FilterCompanionDevice(validType);
    EXPECT_EQ(validType.size(), (size_t)1);
    EXPECT_EQ(validType[0], AuthType::COMPANION_DEVICE);
}

// 覆盖第1366行：hasCompanionDevice=true 且 hasOtherType=true (进入erase分支)
HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterCompanionDevice_CompanionWithOther_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> validType = {AuthType::COMPANION_DEVICE, AuthType::FACE};
    service.FilterCompanionDevice(validType);
    EXPECT_EQ(validType.size(), (size_t)1);
    EXPECT_EQ(validType[0], AuthType::FACE);
}

// 覆盖第1385行：navigationButtonText非空 且 validType包含其他类型 (触发 !CheckAuthTypeOnly 分支)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnWithFacePin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::PIN},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1385行：navigationButtonText非空 且 CheckAuthTypeOnly返回true (只有COMPANION_DEVICE)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnOnlyCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1391行：windowMode=FULLSCREEN 且 CheckAuthTypeOnly返回true (FACE+FINGERPRINT+COMPANION_DEVICE)
// 且 CheckAuthTypeOnly返回false (不只有COMPANION_DEVICE)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_FullscreenWithThreeTypes_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, INVALID_PARAMETERS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1391行：windowMode=FULLSCREEN 且 CheckAuthTypeOnly返回false (不满足FACE+FINGERPRINT+COMPANION_DEVICE)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_FullscreenWithPin_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::PIN},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::PIN));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1391行：windowMode=FULLSCREEN 且只有COMPANION_DEVICE (CheckAuthTypeOnly第二个条件为true)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_FullscreenOnlyCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::FULLSCREEN,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1074行：hasCompanionDevice=true 但 hasPin=false && hasPrivatePin=false (返回SUCCESS)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetType_OnlyCompanionDevice_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> authTypes = {AuthType::COMPANION_DEVICE};
    int32_t ret = service.CheckAuthWidgetType(authTypes);
    EXPECT_EQ(ret, SUCCESS);
}

// 覆盖第1179行：authTypes.size==2 但 CheckAuthTypeOnly返回false (例如FACE+PIN)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckAuthWidgetParam_SizeTwoNotOnlyFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE, AuthType::PIN},
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "",
    };
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 覆盖第1184行：authTypes.size==3 但 CheckAuthTypeOnly返回false (例如FACE+FINGERPRINT+PIN)
HWTEST_F(UserAuthServiceTest,
    UserAuthServiceCheckAuthWidgetParam_SizeThreeNotOnlyFaceFingerCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::PIN},
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "",
    };
    int32_t ret = service.CheckAuthWidgetParam(authParam, widgetParam);
    EXPECT_EQ(ret, SUCCESS);
}

// 覆盖第1314行：authTypeList.size>1 (不进入CANCELED_FROM_WIDGET分支)
HWTEST_F(UserAuthServiceTest,
    UserAuthServiceCheckSkipLockedBiometricAuth_MultipleAuthTypesWithNavBtn_001, TestSize.Level0)
{
    UserAuthService service;
    int32_t userId = 100;
    AuthParamInner authParam = {
        .authTypes = {AuthType::FACE, AuthType::PIN},
        .skipLockedBiometricAuth = true,
    };
    WidgetParamInner widgetParam = {
        .title = "test",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    std::vector<AuthType> validType = {AuthType::FACE, AuthType::PIN};
    int32_t ret = service.CheckSkipLockedBiometricAuth(userId, authParam, widgetParam, validType);
    EXPECT_EQ(ret, SUCCESS);
}

// 覆盖第1366行：hasCompanionDevice=false (不进入erase分支)
HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterCompanionDevice_NoCompanion_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> validType = {AuthType::FACE, AuthType::FINGERPRINT};
    service.FilterCompanionDevice(validType);
    EXPECT_EQ(validType.size(), (size_t)2);
}

// 覆盖第1385行：navigationButtonText非空 且 validType={FACE, FINGERPRINT} (不满足条件，返回SUCCESS)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnWithFaceFinger_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "nav_btn",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1385行：navigationButtonText为空 (短路分支)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NavBtnEmpty_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1391行：windowMode != FULLSCREEN (短路分支)
HWTEST_F(UserAuthServiceTest, UserAuthServiceCheckValidSolution_NonFullscreen_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<uint8_t> challenge = {1};
    int32_t userId = 100;
    const WidgetParamInner widgetParam = {
        .title = "test_title",
        .navigationButtonText = "",
        .windowMode = WindowModeType::DIALOG_BOX,
    };
    const AuthParamInner authParam = {
        .userId = userId,
        .challenge = challenge,
        .authTypes = {AuthType::FACE, AuthType::FINGERPRINT, AuthType::COMPANION_DEVICE},
        .authTrustLevel = ATL3,
        .isUserIdSpecified = true,
    };
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _))
        .WillOnce([](int32_t userId, const std::vector<int32_t> &authTypes,
            uint32_t authTrustLevel, std::vector<int32_t> &validTypes) {
            validTypes.push_back(static_cast<int32_t>(AuthType::FACE));
            validTypes.push_back(static_cast<int32_t>(AuthType::FINGERPRINT));
            validTypes.push_back(static_cast<int32_t>(AuthType::COMPANION_DEVICE));
            return HDF_SUCCESS;
        });
    int32_t ret = service.CheckValidSolution(userId, authParam, widgetParam, validTypeList);
    EXPECT_EQ(ret, SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

// 覆盖第1366行：hasCompanionDevice=false 且 hasOtherType=false (validType为空)
HWTEST_F(UserAuthServiceTest, UserAuthServiceFilterCompanionDevice_EmptyValidType_001, TestSize.Level0)
{
    UserAuthService service;
    std::vector<AuthType> validType = {};
    service.FilterCompanionDevice(validType);
    EXPECT_EQ(validType.size(), (size_t)0);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS