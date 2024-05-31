/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cinttypes>
#include <string>

#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_client_impl.h"
#include "user_auth_napi_helper.h"
#include "user_auth_common_defines.h"

#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::string AUTH_EVENT_RESULT = "result";
const std::string AUTH_PARAM_CHALLENGE = "challenge";
const std::string AUTH_PARAM_AUTHTYPE = "authType";
const std::string AUTH_PARAM_AUTHTRUSTLEVEL = "authTrustLevel";
const std::string AUTH_PARAM_REUSEUNLOCKRESULT = "reuseUnlockResult";
const std::string WIDGET_PARAM_TITLE = "title";
const std::string WIDGET_PARAM_NAVIBTNTEXT = "navigationButtonText";
const std::string WIDGET_PARAM_WINDOWMODE = "windowMode";
const std::string NOTICETYPE = "noticeType";
const std::string REUSEMODE = "reuseMode";
const std::string REUSEDURATION = "reuseDuration";

namespace WidgetType {
    constexpr int32_t TITLE_MAX = 500;
    constexpr int32_t BUTTON_MAX = 60;
}
napi_value UserAuthInstanceV10::GetEnrolledState(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_ONE] = {nullptr};
    size_t argc = ARGS_ONE;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_ONE) {
        IAM_LOGE("parms error");
        std::string msgStr = "Parameter error. The number of parameters should be 1.";
        napi_throw(env, UserAuthNapiHelper::GenerateErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr));
        return nullptr;
    }
    int32_t type;
    if (UserAuthNapiHelper::GetInt32Value(env, argv[PARAM0], type) != napi_ok) {
        IAM_LOGE("napi_get_value_int32 fail");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    if (!UserAuthNapiHelper::CheckUserAuthType(type)) {
        IAM_LOGE("CheckUserAuthType fail");
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::TYPE_NOT_SUPPORT));
        return nullptr;
    }
    AuthType authType = AuthType(type);
    EnrolledState enrolledState = {};
    int32_t code = UserAuthClientImpl::Instance().GetEnrolledState(API_VERSION_12, authType, enrolledState);
    if (code != SUCCESS) {
        IAM_LOGE("failed to get enrolled state %{public}d", code);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env,
            UserAuthResultCode(UserAuthNapiHelper::GetResultCodeV10(code))));
        return nullptr;
    }
    return DoGetEnrolledStateResult(env, enrolledState);
}

napi_value UserAuthInstanceV10::DoGetEnrolledStateResult(napi_env env, EnrolledState enrolledState)
{
    IAM_LOGI("start");
    napi_value eventInfo;
    napi_status ret = napi_create_object(env, &eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    int32_t credentialDigest = static_cast<int32_t>(enrolledState.credentialDigest);
    int32_t credentialCount = static_cast<int32_t>(enrolledState.credentialCount);
    IAM_LOGI("get enrolled state success, credentialDigest = %{public}d, credentialCount = %{public}d",
        credentialDigest, credentialCount);
    ret = UserAuthNapiHelper::SetInt32Property(env, eventInfo, "credentialDigest", credentialDigest);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env, eventInfo, "credentialCount", credentialCount);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        napi_throw(env, UserAuthNapiHelper::GenerateBusinessErrorV9(env, UserAuthResultCode::GENERAL_ERROR));
        return nullptr;
    }
    IAM_LOGI("get enrolled state end");
    return eventInfo;
}

UserAuthInstanceV10::UserAuthInstanceV10(napi_env env) : callback_(Common::MakeShared<UserAuthCallbackV10>(env))
{
    if (callback_ == nullptr) {
        IAM_LOGE("get null callback");
    }
    authParam_.authTrustLevel = AuthTrustLevel::ATL1;
    widgetParam_.navigationButtonText = "";
    widgetParam_.title = "";
    widgetParam_.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
}

UserAuthResultCode UserAuthInstanceV10::InitChallenge(napi_env env, napi_value value)
{
    authParam_.challenge.clear();
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("challenge is null");
        std::string msgStr = "Parameter error. The type of \"challenge\" must be Uint8Array.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    ret = UserAuthNapiHelper::GetUint8ArrayValue(env, value, MAX_CHALLENG_LEN, authParam_.challenge);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The length of \"challenge\" connot exceed 32.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
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
        std::string msgStr = "Parameter error. The type of \"authType\" must be array.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    uint32_t length = 0;
    napi_get_array_length(env, value, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value jsValue = nullptr;
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        napi_get_element(env, value, i, &jsValue);
        if (jsValue == nullptr) {
            napi_close_handle_scope(env, scope);
            continue;
        }
        int32_t value = 0;
        napi_status ret = UserAuthNapiHelper::GetInt32Value(env, jsValue, value);
        napi_close_handle_scope(env, scope);
        if (ret != napi_ok) {
            IAM_LOGE("napi authType GetUint32Value fail:%{public}d", ret);
            std::string msgStr = "Parameter error. The type of \"authType\" must be number.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        IAM_LOGI("napi get authType:%{public}d", value);
        if (!UserAuthNapiHelper::CheckUserAuthType(value)) {
            IAM_LOGE("authType is illegal, %{public}d", value);
            return UserAuthResultCode::TYPE_NOT_SUPPORT;
        }
        auto iter = std::find(authParam_.authTypes.begin(), authParam_.authTypes.end(), static_cast<AuthType>(value));
        if (iter != authParam_.authTypes.end()) {
            IAM_LOGE("napi authType:%{public}d exist", value);
            std::string msgStr = "Parameter error. The type of \"authType\" must be AuthType.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        authParam_.authTypes.push_back(static_cast<AuthType>(value));
    }

    IAM_LOGI("authType size:%{public}zu", authParam_.authTypes.size());
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitAuthTrustLevel(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("authTrustLevel is null");
        std::string msgStr = "Parameter error. The type of \"authTrustLevel\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    uint32_t authTrustLevel;
    ret = UserAuthNapiHelper::GetUint32Value(env, value, authTrustLevel);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"authTrustLevel\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    if (!UserAuthNapiHelper::CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("AuthTrustLevel fail:%{public}u", authTrustLevel);
        return UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }
    authParam_.authTrustLevel = AuthTrustLevel(authTrustLevel);
    IAM_LOGI("authTrustLevel:%{public}u", authParam_.authTrustLevel);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitReuseUnlockResult(napi_env env, napi_value value)
{
    uint32_t reuseMode;
    uint32_t reuseDuration;
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, REUSEMODE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", REUSEMODE.c_str());
        std::string msgStr = "Parameter error. \"reuseMode\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_reuseMode = UserAuthNapiHelper::GetNamedProperty(env, value, REUSEMODE);
    napi_status ret = UserAuthNapiHelper::GetUint32Value(env, napi_reuseMode, reuseMode);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"reuseMode\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam_.reuseUnlockResult.reuseMode = ReuseMode(reuseMode);
    if (!UserAuthNapiHelper::HasNamedProperty(env, value, REUSEDURATION)) {
        IAM_LOGE("propertyName: %{public}s not exists.", REUSEDURATION.c_str());
        std::string msgStr = "Parameter error. \"reuseDuration\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_reuseDuration = UserAuthNapiHelper::GetNamedProperty(env, value, REUSEDURATION);
    ret = UserAuthNapiHelper::GetUint32Value(env, napi_reuseDuration, reuseDuration);
    if (ret != napi_ok) {
        IAM_LOGE("GetUint32Value fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"reuseDuration\" must be number.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam_.reuseUnlockResult.reuseDuration = reuseDuration;
    if (!UserAuthNapiHelper::CheckReuseUnlockResult(authParam_.reuseUnlockResult)) {
        IAM_LOGE("ReuseUnlockResult fail");
        std::string msgStr = "Parameter error. The type of \"reuseUnlockResult\" must be ReuseUnlockResult.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    authParam_.reuseUnlockResult.isReuse = true;
    IAM_LOGI("reuseMode: %{public}u, reuseDuration: %{public}" PRIu64, authParam_.reuseUnlockResult.reuseMode,
        authParam_.reuseUnlockResult.reuseDuration);
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitAuthParam(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("authParam is null");
        std::string msgStr = "Parameter error. \"authParam\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_CHALLENGE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_CHALLENGE.c_str());
        std::string msgStr = "Parameter error. \"challenge\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_challenge = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_CHALLENGE);
    UserAuthResultCode errorCode = InitChallenge(env, napi_challenge);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitChallenge fail:%{public}d", errorCode);
        return UserAuthResultCode::OHOS_INVALID_PARAM;
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_AUTHTYPE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_AUTHTYPE.c_str());
        std::string msgStr = "Parameter error. \"authType\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_authType = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_AUTHTYPE);
    errorCode = InitAuthType(env, napi_authType);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthType fail:%{public}d", errorCode);
        return errorCode;
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_AUTHTRUSTLEVEL)) {
        IAM_LOGE("propertyName: %{public}s not exists.", AUTH_PARAM_AUTHTRUSTLEVEL.c_str());
        std::string msgStr = "Parameter error. \"authTrustLevel\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    napi_value napi_authTrustLevel = UserAuthNapiHelper::GetNamedProperty(env, value, AUTH_PARAM_AUTHTRUSTLEVEL);
    errorCode = InitAuthTrustLevel(env, napi_authTrustLevel);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("InitAuthTrustLevel fail:%{public}d", errorCode);
        return errorCode;
    }
    errorCode = ProcessReuseUnlockResult(env, value);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::ProcessReuseUnlockResult(napi_env env, napi_value value)
{
    if (UserAuthNapiHelper::HasNamedProperty(env, value, AUTH_PARAM_REUSEUNLOCKRESULT)) {
        napi_value napi_reuseUnlockResult = UserAuthNapiHelper::GetNamedProperty(env, value,
            AUTH_PARAM_REUSEUNLOCKRESULT);
        UserAuthResultCode errorCode = InitReuseUnlockResult(env, napi_reuseUnlockResult);
        if (errorCode != UserAuthResultCode::SUCCESS) {
            IAM_LOGE("InitReuseUnlockResult fail:%{public}d", errorCode);
            return errorCode;
        }
    } else {
        authParam_.reuseUnlockResult.isReuse = false;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::InitWidgetParam(napi_env env, napi_value value)
{
    napi_status ret = UserAuthNapiHelper::CheckNapiType(env, value, napi_null);
    if (ret == napi_ok) {
        IAM_LOGI("widgetParam is null");
        std::string msgStr = "Parameter error. \"widgetParam\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    if (!UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_TITLE)) {
        IAM_LOGE("propertyName: %{public}s not exists.", WIDGET_PARAM_TITLE.c_str());
        std::string msgStr = "Parameter error. \"title\" is a mandatory parameter and is left unspecified.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    std::string title = UserAuthNapiHelper::GetStringPropertyUtf8(env, value, WIDGET_PARAM_TITLE);
    if (title == "" || title.length() > WidgetType::TITLE_MAX) {
        IAM_LOGE("title is invalid. size: %{public}zu", title.length());
        std::string msgStr = "Parameter error. The length of \"title\" connot exceed 500.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    widgetParam_.title = title;

    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_NAVIBTNTEXT)) {
        std::string naviBtnTxt = UserAuthNapiHelper::GetStringPropertyUtf8(env, value, WIDGET_PARAM_NAVIBTNTEXT);
        if (naviBtnTxt == "" || naviBtnTxt.length() > WidgetType::BUTTON_MAX) {
            IAM_LOGE("navigation button text is invalid, size: %{public}zu", naviBtnTxt.length());
            std::string msgStr = "Parameter error. The length of \"navigationButtonText\" connot exceed 60.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        widgetParam_.navigationButtonText = naviBtnTxt;
    }

    UserAuthResultCode errorCode = ProcessWindowMode(env, value);
    if (errorCode != UserAuthResultCode::SUCCESS) {
        return errorCode;
    }
    return UserAuthResultCode::SUCCESS;
}

UserAuthResultCode UserAuthInstanceV10::ProcessWindowMode(napi_env env, napi_value value)
{
    if (UserAuthNapiHelper::HasNamedProperty(env, value, WIDGET_PARAM_WINDOWMODE)) {
        napi_value napi_windowModeType = UserAuthNapiHelper::GetNamedProperty(env, value, WIDGET_PARAM_WINDOWMODE);
        uint32_t windowMode;
        napi_status ret = UserAuthNapiHelper::GetUint32Value(env, napi_windowModeType, windowMode);
        if (ret != napi_ok) {
            IAM_LOGE("napi authType GetUint32Value fail:%{public}d", ret);
            std::string msgStr = "Parameter error. The type of \"windowMode\" must be number.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
        switch (windowMode) {
            case WindowModeType::DIALOG_BOX:
            case WindowModeType::FULLSCREEN:
                widgetParam_.windowMode = static_cast<WindowModeType>(windowMode);
                break;
            default:
                IAM_LOGE("windowMode type not support.");
                std::string msgStr = "Parameter error. The type of \"windowMode\" must be WindowModeType.";
                return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
    }

    IAM_LOGI("widgetParam title:%{public}s, navBtnText:%{public}s, winMode:%{public}u",
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
        std::string msgStr = "Invalid authentication parameters. The number of parameters should be 2";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    UserAuthResultCode errCode = InitAuthParam(env, argv[PARAM0]);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("AuthParamInner type error, errorCode: %{public}d", errCode);
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
    ret = napi_get_named_property(env, value, "onResult", &callbackValue);
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
        std::string msgStr = "Parameter error. The number of parameters should be 2";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    static const size_t maxLen = 10;
    char str[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], str, len);
    if (ret != napi_ok) {
        IAM_LOGE("getAuthInstance on GetStrValue fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"type\" must be string.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    auto callbackRef = GetCallback(env, argv[PARAM1]);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("getAuthInstance on GetCallback fail");
        std::string msgStr = "Parameter error. The type of \"callback\" must be IAuthCallback.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    if (str == AUTH_EVENT_RESULT) {
        IAM_LOGI("getAuthInstance on SetResultCallback");
        if (callback_->HasResultCallback()) {
            IAM_LOGE("callback has been registerred");
            return UserAuthResultCode::GENERAL_ERROR;
        }
        callback_->SetResultCallback(callbackRef);
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("getAuthInstance on invalid event:%{public}s", str);
        std::string msgStr = "Parameter error. The value of \"type\" must be \"result\".";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
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
        std::string msgStr = "Parameter error. The number of parameters should be 1 or 2";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }
    static const size_t maxLen = 10;
    char str[maxLen] = {0};
    size_t len = maxLen;
    ret = UserAuthNapiHelper::GetStrValue(env, argv[PARAM0], str, len);
    if (ret != napi_ok) {
        IAM_LOGE("UserAuthResultCode off GetStrValue fail:%{public}d", ret);
        std::string msgStr = "Parameter error. The type of \"type\" must be string.";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
    }

    if (argc == ARGS_TWO) {
        auto callbackRef = GetCallback(env, argv[PARAM1]);
        if (callbackRef == nullptr || !callbackRef->IsValid()) {
            IAM_LOGE("GetCallback fail");
            std::string msgStr = "Parameter error. The type of \"callback\" must be IAuthCallback.";
            return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
        }
    }

    if (str == AUTH_EVENT_RESULT) {
        if (!callback_->HasResultCallback()) {
            IAM_LOGE("no callback registerred yet");
            return UserAuthResultCode::GENERAL_ERROR;
        }
        callback_->ClearResultCallback();
        IAM_LOGI("UserAuthResultCode off clear result callback");
        return UserAuthResultCode::SUCCESS;
    } else {
        IAM_LOGE("invalid event:%{public}s", str);
        std::string msgStr = "Parameter error. The value of \"type\" must be \"result\".";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
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
        std::string msgStr = "Parameter error. The number of parameters should be 0";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
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
        std::string msgStr = "Parameter error. The number of parameters should be 0";
        return UserAuthNapiHelper::ThrowErrorMsg(env, UserAuthResultCode::OHOS_INVALID_PARAM, msgStr);
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
