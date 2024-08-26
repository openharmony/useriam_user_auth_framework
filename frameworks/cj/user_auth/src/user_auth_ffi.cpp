/*
* Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "cj_lambda.h"
#include "user_auth_client_impl.h"

#include "user_auth_ffi.h"

using namespace OHOS::UserIam::UserAuth;

int32_t Ffi_UserAuth_GetAvailableStatus(const uint32_t authType, const uint32_t authTrustLevel) {
    constexpr int32_t API_VERSION_9 = 9;
    return UserAuthClientImpl::Instance().GetAvailableStatus(API_VERSION_9, AuthType(authType),
                                                             AuthTrustLevel(authTrustLevel));
}

int32_t Ffi_UserAuth_GetEnrolledState(const uint32_t authType, EnrolledState *enrolledState) {
    constexpr int32_t API_VERSION_12 = 12;
    return UserAuthClientImpl::Instance().GetEnrolledState(API_VERSION_12, AuthType(authType), *enrolledState);
}

UserAuthCallbackCj *Ffi_UserAuth_NewCb(void (*const callback)(CUserAuthResult)) {
    return new UserAuthCallbackCj(CJLambda::Create(callback));
}

void Ffi_UserAuth_DeleteCb(const UserAuthCallbackCj *callbackPtr) {
    delete callbackPtr;
}

uint64_t Ffi_UserAuth_Start(const CAuthParam &authParam, const CWidgetParam &widgetParam,
                            UserAuthCallbackCj *callbackPtr) {
    constexpr int32_t API_VERSION_10 = 10;
    std::vector<AuthType> authTypes;
    for (int i = 0; i < authParam.authTypesLen; ++i) {
        authTypes.push_back(AuthType(authParam.authTypes[i]));
    }
    AuthParamInner authParamInner{
        .challenge = std::vector<uint8_t>(authParam.challenge, authParam.challenge + authParam.authTypesLen),
        .authTypes = authTypes,
        .authTrustLevel = AuthTrustLevel(authParam.authTrustLevel),
    };
    if (authParam.isReuse) {
        authParamInner.reuseUnlockResult = {
            .isReuse = true,
            .reuseMode = ReuseMode(authParam.reuseMode),
            .reuseDuration = authParam.reuseDuration,
        };
    }
    WidgetParam widgetInner = {
        .title = widgetParam.title,
        .navigationButtonText = widgetParam.navigationButtonText ? widgetParam.navigationButtonText : nullptr,
        .windowMode = WindowModeType::UNKNOWN_WINDOW_MODE,
    };
    if (callbackPtr == nullptr) {
        return UserAuthClientImpl::Instance().BeginWidgetAuth(API_VERSION_10, authParamInner, widgetInner,
                                                              std::make_shared<UserAuthCallbackCj>());
    }
    const auto callback = std::shared_ptr<UserAuthCallbackCj>(
        callbackPtr, [](UserAuthCallbackCj *) {
            /* dont free, resource will free in Ffi_UserAuth_DeleteCb */
        });
    return UserAuthClientImpl::Instance().BeginWidgetAuth(API_VERSION_10, authParamInner, widgetInner, callback);
}

int32_t Ffi_UserAuth_Cancel(const uint64_t contextId) {
    return UserAuthClientImpl::GetInstance().CancelAuthentication(contextId);
}
