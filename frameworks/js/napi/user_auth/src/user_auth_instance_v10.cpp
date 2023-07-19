/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "user_auth_instance_v10.h"

#include <string>

#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_client_impl.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::string AUTH_EVENT_RESULT = "result";
const std::string AUTH_PARAM_CHALLENGE = "challenge";
const std::string AUTH_PARAM_AUTHTYPE = "authType";
const std::string AUTH_PARAM_AUTHTRUSTLEVEL = "authTrustLevel";
const std::string WIDGET_PARAM_TITLE = "title";
const std::string WIDGET_PARAM_NABTNTEXT = "navigationButtonText";
const std::string WIDGET_PARAM_WINDOWMODE = "windowMode";
const std::string NOTICETYPE = "noticeType";
constexpr int32_t TITLE_MAX = 500;
constexpr int32_t BUTTON_MAX = 60;

UserAuthInstanceV10::UserAuthInstanceV10(napi_env env) : callback_(Common::MakeShared<UserAuthCallbackV10>(env))
{
    if (callback_ == nullptr) {
        IAM_LOGE("get null callback");
    }
}

UserAuthResultCode UserAuthInstanceV10::CheckAuthType(uint32_t authType)
{
    if ((int32_t)authType != AuthType::PIN && (int32_t)authType != AuthType::FACE &&
        (int32_t)authType != AuthType::FINGERPRINT) {
        IAM_LOGE("authType check fail:%{public}d", authType);
        return UserAuthResultCode::TYPE_NOT_SUPPORT;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::CheckAuthTrustLevel(uint32_t authTrustLevel)
{
    if (authTrustLevel != AuthTrustLevel::ATL1 && authTrustLevel != AuthTrustLevel::ATL2 &&
        authTrustLevel != AuthTrustLevel::ATL3 && authTrustLevel != AuthTrustLevel::ATL4) {
        IAM_LOGE("authTrustLevel check fail:%{public}d", authTrustLevel);
        return UserAuthResultCode::TYPE_NOT_SUPPORT;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitChallenge(napi_env env, napi_value value)
{
    authParam_.challenge.clear();
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("challenge is null");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    ret = UserAuthNapiHelper::GetUint8ArrayValue(env, value, MAX_CHALLENG_LEN, authParam_.challenge);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    IAM_LOGI("challenge size:%{public}zu", authParam_.challenge.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitAuthType(napi_env env, napi_value value)
{
    bool isArray = false;
    napi_is_array(env, value, &isArray);
    if (!isArray) {
        IAM_LOGI("authType is not array");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    uint32_t length = 0;
    napi_get_array_length(env, value, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value jsAt = nullptr;
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        napi_get_element(env, value, i, &jsAt);
        if (jsAt == nullptr) {
            continue;
        }
        uint32_t at;
        napi_status ret = UserAuthNapiHelper::GetUint32Value(env, jsAt, at);
        if (ret != napi_ok) {
            IAM_LOGE("napi authType GetUint32Value fail:%{public}d", ret);
            continue;
        }
        UserAuthResultCode errCode = CheckAuthType(at);
        if (errCode != UserAuthResultCode::SUCCESS) {
            IAM_LOGE("authType is illegal, %{public}ud", at);
            return errCode;
        }
        IAM_LOGI("napi authType: %{public}ud", at);
        authParam_.authType.push_back(static_cast<AuthType>(at));
        napi_close_handle_scope(env, scope);
    }

    IAM_LOGI("authType size:%{public}zu", authParam_.authType.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitAuthParam(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("authParam is null");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_CHALLENGE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_CHALLENGE.c_str());
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    napi_value napi_challenge = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_CHALLENGE);
    UserAuthResultCode errorCode = InitChallenge(env, napi_challenge);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitChallenge fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_AUTHTYPE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_AUTHTYPE.c_str());
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    napi_value napi_authType = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_AUTHTYPE);
    errorCode = InitAuthType(env, napi_authType);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthType fail:%{public}d", errorCode);
        return errorCode;
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_AUTHTRUSTLEVEL)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_AUTHTRUSTLEVEL.c_str());
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    napi_value napi_authTrustLeval = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_AUTHTRUSTLEVEL);
    uint32_t authTrustLevel;
    ret = UserAuthNapiHelper::GetUint32Value(env, napi_authTrustLeval, authTrustLevel);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    errorCode = CheckAuthTrustLevel(authTrustLevel);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("AuthTrustLeval fail:%{public}d", errorCode);
        return errorCode;
    }
    authParam_.authTrustLevel = AuthTrustLevel(authTrustLevel);

    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitWidgetParam(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("widgetParam is null");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_TITLE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", WIDGET_PARAM_TITLE.c_str());
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    std::string title = UserAuthNapiHelper::GetStringPropertyUtf8(env, value, WIDGET_PARAM_TITLE);
    if (title == "") {
        IAM_LOGE("title is invalid");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    if (title.length() > TITLE_MAX) {
        IAM_LOGE("title text too long. size: %{public}zu", title.length());
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    widgetParam_.title = title;

    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_NABTNTEXT)) {
        std::string ngtBtnTxt = UserAuthNapiHelper::GetStringPropertyUtf8(env, value, WIDGET_PARAM_NABTNTEXT);
        if (ngtBtnTxt.length() > BUTTON_MAX) {
            IAM_LOGE("button text too long. size: %{public}zu", ngtBtnTxt.length());
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
        widgetParam_.navigationButtonText = ngtBtnTxt;
    }

    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_WINDOWMODE)) {
        napi_value napi_windowModeType = UserAuthNapiHelper::GetNamedProperty(env, value, WIDGET_PARAM_WINDOWMODE);
        uint32_t windowMode;
        ret = UserAuthNapiHelper::GetUint32Value(env, napi_windowModeType, windowMode);
        switch (windowMode) {
            case WindowModeType::DIALOG_BOX:
                widgetParam_.windowMode = WindowModeType::DIALOG_BOX;
                break;
            case WindowModeType::FULLSCREEN:
                widgetParam_.windowMode = WindowModeType::FULLSCREEN;
                break;
            default:
                IAM_LOGE("windowMode type not support.");
                return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
    }

    IAM_LOGI("widgetParam title:%{public}s, navBtnText:%{public}s, winMode:%{public}ud",
        widgetParam_.title.c_str(), widgetParam_.navigationButtonText.c_str(),
        static_cast<uint32_t>(widgetParam_.windowMode));
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::Init(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_TWO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    UserAuthResultCode errCode = InitAuthParam(env, argv[PARAM0]);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("AuthParam type error, errorCode: %{public}d", errCode);
        return errCode;
    }

    errCode = InitWidgetParam(env, argv[PARAM1]);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("WidgetParam type error, errorCode: %{public}d", errCode);
        return errCode;
    }

    IAM_LOGE("Init SUCCESS");
    return UserAuthResultCode::SUCCESS;
}

std::shared_ptr<JsRefHolder> UserAuthInstanceV10::GetCallback(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_object);
    if (ret != napi_ok) {
        IAM_LOGE("CheckNapiType fail:%{public}d", ret);
        return nullptr;
    }
    napi_value callbackValue;
    ret = napi_get_named_property(env, value, "callback", &callbackValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_named_property fail:%{public}d", ret);
        return nullptr;
    }
    return Common::MakeShared<JsRefHolder>(env, callbackValue);
}

UserAuthResultCode UserAuthInstanceV10::On(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("getAuthInstance on callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("getAuthInstance on napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_TWO) {
        IAM_LOGE("getAuthInstance on invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    static const size_t maxLen = 10;
    char str[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], str, len);
    if (ret != napi_ok) {
        IAM_LOGE("getAuthInstance on GetStrValue fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    auto callbackRef = GetCallback(env, argv[PARAM1]);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("getAuthInstance on GetCallback fail");
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    if (str == AUTH_EVENT_RESULT) {
        IAM_LOGI("getAuthInstance on SetResultCallback");
        if (callback_->GetResultCallback() != nullptr) {
            IAM_LOGE("callback has been register");
            return UserAuthResultCode::GENERAL_ERROR;
        }
        callback_->SetResultCallback(callbackRef);
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("getAuthInstance on invalid event:%{public}s", str);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
}

UserAuthResultCode UserAuthInstanceV10::Off(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("userAuthInstance off callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("userAuthInstance off napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_TWO && argc != ARGS_ONE) {
        IAM_LOGE("userAuthInstance off invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    static const size_t maxLen = 10;
    char str[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], str, len);
    if (ret != napi_ok) {
        IAM_LOGE("UserAuthResultCode off GetStrValue fail:%{public}d", ret);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (argc == ARGS_TWO) {
        auto callbackRef = GetCallback(env, argv[PARAM1]);
        if (callbackRef == nullptr || !callbackRef->IsValid()) {
            IAM_LOGE("GetCallback fail");
            return UserAuthResultCode::OHOS_INVALID_PARAM;
        }
    }

    if (str == AUTH_EVENT_RESULT) {
        if (callback_->GetResultCallback() == nullptr) {
            IAM_LOGE("no callback register yet");
            return UserAuthResultCode::GENERAL_ERROR;
        }
        callback_->ClearResultCallback();
        IAM_LOGI("UserAuthResultCode off clear result callback");
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("invalid event:%{public}s", str);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
}

UserAuthResultCode UserAuthInstanceV10::Start(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_ZERO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (isAuthStarted_) {
        IAM_LOGE("auth already started");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    contextId_ = UserAuthClientImpl::Instance().BeginWidgetAuth(API_VERSION_10,
        authParam_, widgetParam_, callback_);
    isAuthStarted_ = true;
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::Cancel(napi_env env, napi_callback_info info)
{
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail:%{public}d", ret);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    if (argc != ARGS_ZERO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (!isAuthStarted_) {
        IAM_LOGE("auth not started");
        return UserAuthResultCode::GENERAL_ERROR;
    }
    int32_t result = UserAuthClient::GetInstance().CancelAuthentication(contextId_);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("CancelAuthentication fail:%{public}d", result);
        return UserAuthResultCode(UserAuthNapiHelper::GetResultCodeV10(result));
    }
    isAuthStarted_ = false;
    return UserAuthResultCode::SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
