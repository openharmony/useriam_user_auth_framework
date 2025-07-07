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

#include "napi_base_context.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "user_auth_api_event_reporter.h"
#include "user_auth_helper.h"
#include "user_auth_client_impl.h"
#include "user_auth_common_defines.h"
#include "user_auth_napi_helper.h"
#include "user_auth_param_utils.h"

#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const std::string AUTH_EVENT_RESULT = "result";
}

UserAuthInstanceV10::UserAuthInstanceV10(napi_env env) : callback_(Common::MakeShared<UserAuthCallbackV10>(env))
{
    if (callback_ == nullptr) {
        IAM_LOGE("get null callback");
    }
    authParam_.authTrustLevel = AuthTrustLevel::ATL1;
    authParam_.userId = INVALID_USER_ID;
    widgetParam_.navigationButtonText = "";
    widgetParam_.title = "";
    widgetParam_.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
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

    UserAuthResultCode errCode = UserAuthParamUtils::InitAuthParam(env, argv[PARAM0], authParam_);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("AuthParamInner type error, errorCode: %{public}d", errCode);
        return errCode;
    }

    errCode = UserAuthParamUtils::InitWidgetParam(env, argv[PARAM1], widgetParam_, context_);
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
    modalCallback_ = Common::MakeShared<UserAuthModalCallback>(context_);
    contextId_ = UserAuthNapiClientImpl::Instance().BeginWidgetAuth(API_VERSION_10,
        authParam_, widgetParam_, callback_, modalCallback_);
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
        return UserAuthResultCode(UserAuthHelper::GetResultCodeV10(result));
    }
    isAuthStarted_ = false;
    return UserAuthResultCode::SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
