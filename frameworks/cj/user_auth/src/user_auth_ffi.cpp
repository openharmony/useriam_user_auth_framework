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

int32_t FfiUserAuthGetAvailableStatus(const uint32_t authType, const uint32_t authTrustLevel)
{
    constexpr int32_t API_VERSION_9 = 9;
    return UserAuthClientImpl::Instance().GetNorthAvailableStatus(API_VERSION_9, AuthType(authType),
        AuthTrustLevel(authTrustLevel));
}

int32_t FfiUserAuthGetEnrolledState(const uint32_t authType, EnrolledState *enrolledState)
{
    constexpr int32_t API_VERSION_12 = 12;
    return UserAuthClientImpl::Instance().GetEnrolledState(API_VERSION_12, AuthType(authType), *enrolledState);
}

CjUserAuthCallback *FfiUserAuthNewCb(void (*const callback)(CjUserAuthResult))
{
    return new CjUserAuthCallback(CJLambda::Create(callback));
}

void FfiUserAuthDeleteCb(const CjUserAuthCallback *callbackPtr)
{
    delete callbackPtr;
}

uint64_t FfiUserAuthStart(const CjAuthParam &authParam, const CjWidgetParam &widgetParam,
    CjUserAuthCallback *callbackPtr)
{
    constexpr int32_t API_VERSION_10 = 10;
    std::vector<AuthType> authTypes;
    for (int i = 0; i < authParam.authTypesLen; ++i) {
        authTypes.push_back(AuthType(authParam.authTypes[i]));
    }
    WidgetAuthParam authParamInner{
        .userId = INVALID_USER_ID,
        .challenge = std::vector<uint8_t>(authParam.challenge, authParam.challenge + authParam.challengeLen),
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
                                                              std::make_shared<CjUserAuthCallback>());
    }
    const auto callback = std::shared_ptr<CjUserAuthCallback>(
        callbackPtr, [](CjUserAuthCallback *) {
             // don't free, resource will be freed in FfiUserAuthDeleteCb
        });
    return UserAuthClientImpl::Instance().BeginWidgetAuth(API_VERSION_10, authParamInner, widgetInner, callback);
}

int32_t FfiUserAuthCancel(const uint64_t contextId)
{
    return UserAuthClientImpl::GetInstance().CancelAuthentication(contextId);
}

int32_t FfiUserAuthQueryReusableAuthResult(int32_t userId, const CjAuthParam &authParam,
    CjReuseAuthResult *reuseAuthResult)
{
    std::vector<AuthType> authTypes;
    for (int i = 0; i < authParam.authTypesLen; ++i) {
        authTypes.push_back(AuthType(authParam.authTypes[i]));
    }
    WidgetAuthParam authParamInner{
        .userId = userId,
        .challenge = std::vector<uint8_t>(authParam.challenge, authParam.challenge + authParam.challengeLen),
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

    std::vector<uint8_t> extraInfo;
    int32_t ret = UserAuthClientImpl::Instance().QueryReusableAuthResult(authParamInner, extraInfo);
    if (ret == SUCCESS) {
        Attributes attributes(extraInfo);
        std::vector<uint8_t> token;
        attributes.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
        reuseAuthResult->token = token.data();
        reuseAuthResult->tokenLen = static_cast<int64_t>(token.size());
    }

    return ret;
}