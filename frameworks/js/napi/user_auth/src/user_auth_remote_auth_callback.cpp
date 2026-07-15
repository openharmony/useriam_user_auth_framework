/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "user_auth_remote_auth_callback.h"

#include <uv.h>

#include "napi/native_node_api.h"
#include "set_widget_param_callback.h"
#include "user_auth_param_utils.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_NAPI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_REMOTE_AUTH_CALLBACK_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct CallbackHolder {
    std::shared_ptr<RemoteAuthCallback> callback {nullptr};
    std::shared_ptr<SetWidgetParamClientCallback> setCallback {nullptr};
    std::vector<uint8_t> challenge {};
    int32_t result {0};
    std::vector<uint8_t> token {};
    int32_t authType {0};
    EnrolledState enrolledState {};
    napi_env env;
};

std::shared_ptr<CallbackHolder> CreateParamCallbackHolder(const std::vector<uint8_t> &challenge,
    const std::shared_ptr<SetWidgetParamClientCallback> &setCallback,
    const std::shared_ptr<RemoteAuthCallback> &callback)
{
    std::shared_ptr<CallbackHolder> holder = Common::MakeShared<CallbackHolder>();
    if (holder == nullptr) {
        IAM_LOGE("holder is null");
        return nullptr;
    }

    holder->callback = callback;
    holder->setCallback = setCallback;
    holder->challenge = challenge;
    return holder;
}

std::shared_ptr<CallbackHolder> CreateResultCallbackHolder(const std::vector<uint8_t> &challenge,
    int32_t result, const Attributes &extraInfo, const std::shared_ptr<RemoteAuthCallback> &callback)
{
    std::shared_ptr<CallbackHolder> holder = Common::MakeShared<CallbackHolder>();
    if (holder == nullptr) {
        IAM_LOGE("holder is null");
        return nullptr;
    }
    holder->callback = callback;
    holder->challenge = challenge;
    holder->result = result;
    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, holder->token)) {
        IAM_LOGE("ATTR_SIGNATURE is null");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, holder->authType)) {
        IAM_LOGE("ATTR_AUTH_TYPE is null");
    }
    if (!extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, holder->enrolledState.credentialDigest)) {
        IAM_LOGE("ATTR_CREDENTIAL_DIGEST is null");
    }
    if (!extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, holder->enrolledState.credentialCount)) {
        IAM_LOGE("ATTR_CREDENTIAL_COUNT is null");
    }
    return holder;
}
}

RemoteAuthCallback::RemoteAuthCallback(napi_env env,
    const std::shared_ptr<JsRefHolder> &widgetParamCallback, const std::shared_ptr<JsRefHolder> &resultCallback)
    : env_(env), widgetParamCallback_(widgetParamCallback), resultCallback_(resultCallback)
{
    if (env_ == nullptr) {
        IAM_LOGE("RemoteAuthCallback get null env");
    }
}

RemoteAuthCallback::~RemoteAuthCallback()
{
}

std::shared_ptr<JsRefHolder> RemoteAuthCallback::GetWidgetParamCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return widgetParamCallback_;
}

std::shared_ptr<JsRefHolder> RemoteAuthCallback::GetResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return resultCallback_;
}

void RemoteAuthCallback::ClearWidgetParamCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    widgetParamCallback_ = nullptr;
}

void RemoteAuthCallback::ClearResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = nullptr;
}

napi_status RemoteAuthCallback::DoGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge, napi_value *result)
{
    IAM_LOGI("start");
    auto callback = GetWidgetParamCallback();
    if (callback == nullptr) {
        IAM_LOGE("GetWidgetParamCallback fail");
        return napi_invalid_arg;
    }

    std::vector<uint8_t> challengeCopy = challenge;
    napi_value napiValue = UserAuthNapiHelper::Uint8VectorToNapiUint8Array(env_, challengeCopy);
    return UserAuthNapiHelper::CallNapiFuncWithResult(env_, callback->Get(), ARGS_ONE, &napiValue, result);
}

void RemoteAuthCallback::OnGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
    const std::shared_ptr<SetWidgetParamClientCallback> &callback)
{
    IAM_LOGI("start");
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<CallbackHolder> holder =
        CreateParamCallbackHolder(challenge, callback, shared_from_this());
    if (holder == nullptr || holder->callback == nullptr || holder->setCallback == nullptr) {
        IAM_LOGE("CreateParamCallbackHolder fail");
        return;
    }
    holder->env = env_;
    auto task = [holder] () {
        IAM_LOGI("start");
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(holder->env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            return;
        }
        napi_value widgetParamValue = nullptr;
        napi_status ret = holder->callback->DoGetRemoteAuthWidgetParam(holder->challenge, &widgetParamValue);
        if (ret != napi_ok) {
            IAM_LOGE("DoGetRemoteAuthWidgetParam fail %{public}d", ret);
            napi_close_handle_scope(holder->env, scope);
            return;
        }
        SetWidgetParamClientCallback::WidgetParamExt widgetParamExt = {};
        std::shared_ptr<UserAuthModalCallback> modalCallback = nullptr;
        ret = holder->callback->ConvertRemoteAuthWidgetParam(holder->env, widgetParamValue, widgetParamExt,
            modalCallback);
        if (ret != napi_ok) {
            IAM_LOGE("ConvertRemoteAuthWidgetParam fail %{public}d", ret);
            napi_close_handle_scope(holder->env, scope);
            return;
        }
        int32_t retCode = holder->setCallback->OnSetRemoteAuthWidgetParam(widgetParamExt, modalCallback);
        if (retCode != SUCCESS) {
            IAM_LOGE("OnSetRemoteAuthWidgetParam fail %{public}d", retCode);
        }
        napi_close_handle_scope(holder->env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::RemoteAuthCallback::OnGetRemoteAuthWidgetParam")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

napi_status RemoteAuthCallback::DoRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t result,
    const std::vector<uint8_t> &token, int32_t authType, EnrolledState enrolledState)
{
    auto resultCallback = GetResultCallback();
    if (resultCallback == nullptr) {
        IAM_LOGE("resultCallback is null");
        return napi_invalid_arg;
    }

    napi_value params[ARGS_TWO];
    std::vector<uint8_t> challengeCopy = challenge;
    napi_value eventInfo = UserAuthNapiHelper::Uint8VectorToNapiUint8Array(env_, challengeCopy);
    if (eventInfo == nullptr) {
        IAM_LOGE("Uint8VectorToNapiUint8Array failed");
        return napi_invalid_arg;
    }
    params[PARAM0] = eventInfo;

    napi_status ret = napi_create_object(env_, &params[PARAM1]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }

    ResultInfo resultInfo = { result, token, authType, enrolledState };
    ret = UserAuthNapiHelper::SetResultInfoProperty(env_, params[PARAM1], resultInfo);
    if (ret != napi_ok) {
        IAM_LOGE("SetResultInfoProperty failed %{public}d", ret);
        return ret;
    }

    return UserAuthNapiHelper::CallVoidNapiFunc(env_, resultCallback->Get(), ARGS_TWO, params);
}

void RemoteAuthCallback::OnRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t result,
    const Attributes &extraInfo)
{
    IAM_LOGI("start, result: %{public}d", result);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<CallbackHolder> holder =
        CreateResultCallbackHolder(challenge, result, extraInfo, shared_from_this());
    if (holder == nullptr || holder->callback == nullptr) {
        IAM_LOGE("CreateResultCallbackHolder fail");
        return;
    }
    holder->env = env_;
    auto task = [holder] () {
        IAM_LOGI("start");
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(holder->env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            return;
        }
        napi_status ret = holder->callback->DoRemoteAuthResult(holder->challenge, holder->result,
            holder->token, holder->authType, holder->enrolledState);
        if (ret != napi_ok) {
            IAM_LOGE("DoSendRemoteAuthResult fail %{public}d", ret);
            napi_close_handle_scope(holder->env, scope);
            return;
        }
        napi_close_handle_scope(holder->env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate,
        "UserAuthNapi::RemoteAuthCallback::OnRemoteAuthResult")) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

napi_status RemoteAuthCallback::ConvertRemoteAuthWidgetParam(napi_env env, napi_value value,
    SetWidgetParamClientCallback::WidgetParamExt &widgetParamExt, std::shared_ptr<UserAuthModalCallback> &modalCallback)
{
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    sptr<OHOS::Rosen::Window> window = nullptr;
    UserAuthResultCode errCode = UserAuthParamUtils::InitWidgetParam(env, value, widgetParamExt, context, window);
    if (errCode != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("WidgetParam type error, errorCode: %{public}d", errCode);
        return napi_invalid_arg;
    }
    if (context == nullptr && window != nullptr) {
        IAM_LOGI("widget type is window");
        modalCallback = Common::MakeShared<UserAuthModalCallback>(window);
    } else {
        IAM_LOGI("widget type is context");
        modalCallback = Common::MakeShared<UserAuthModalCallback>(context);
    }
    return napi_ok;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
