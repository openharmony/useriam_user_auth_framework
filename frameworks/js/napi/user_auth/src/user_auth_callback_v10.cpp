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

#include "user_auth_callback_v10.h"

#include <uv.h>

#include "iam_logger.h"
#include "user_auth_client_impl.h"

#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct ResultCallbackV10Holder {
    std::shared_ptr<UserAuthCallbackV10> callback {nullptr};
    int32_t result {0};
    std::vector<uint8_t> token {};
    int32_t authType {0};
    EnrolledState enrolledState {};
    napi_env env {nullptr};
};

void DestoryResultWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<ResultCallbackV10Holder *>(work->data));
    }
    delete work;
}

void OnResultV10Work(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    ResultCallbackV10Holder *resultHolder = reinterpret_cast<ResultCallbackV10Holder *>(work->data);
    if (resultHolder == nullptr || resultHolder->callback == nullptr) {
        IAM_LOGE("resultHolder is invalid");
        DestoryResultWork(work);
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(resultHolder->env, &scope);
    if (scope == nullptr) {
        IAM_LOGE("scope is invalid");
        DestoryResultWork(work);
        return;
    }
    napi_status ret = resultHolder->callback->DoResultCallback(resultHolder->result, resultHolder->token,
        resultHolder->authType, resultHolder->enrolledState);
    IAM_LOGD("DoResultCallback ret = %{public}d", ret);
    napi_close_handle_scope(resultHolder->env, scope);
    DestoryResultWork(work);
}
}

UserAuthCallbackV10::UserAuthCallbackV10(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAuthCallbackV10 get null env");
    }
}

UserAuthCallbackV10::~UserAuthCallbackV10()
{
}

void UserAuthCallbackV10::SetResultCallback(const std::shared_ptr<JsRefHolder> &resultCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = resultCallback;
}

void UserAuthCallbackV10::ClearResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = nullptr;
}

std::shared_ptr<JsRefHolder> UserAuthCallbackV10::GetResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return resultCallback_;
}

bool UserAuthCallbackV10::HasResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return resultCallback_ != nullptr;
}

napi_status UserAuthCallbackV10::DoResultCallback(int32_t result,
    const std::vector<uint8_t> &token, int32_t authType, EnrolledState enrolledState)
{
    auto resultCallback = GetResultCallback();
    if (resultCallback == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value eventInfo;
    napi_status ret = napi_create_object(env_, &eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "result", result);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }

    if (!token.empty()) {
        ret = UserAuthNapiHelper::SetUint8ArrayProperty(env_, eventInfo, "token", token);
        if (ret != napi_ok) {
            IAM_LOGE("SetUint8ArrayProperty failed %{public}d", ret);
            return ret;
        }
    }

    if (authType == AuthType::PIN ||
        authType == AuthType::FACE ||
        authType == AuthType::FINGERPRINT) {
        ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "authType", authType);
        if (ret != napi_ok) {
            IAM_LOGE("napi_create_int32 failed %{public}d", ret);
            return ret;
        }
    }
    if (UserAuthResultCode(result) == UserAuthResultCode::SUCCESS) {
        ret = UserAuthNapiHelper::SetEnrolledStateProperty(env_, eventInfo, "enrolledState", enrolledState);
        if (ret != napi_ok) {
            IAM_LOGE("SetEnrolledStateProperty failed %{public}d", ret);
            return ret;
        }
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, resultCallback->Get(), ARGS_ONE, &eventInfo);
}

void UserAuthCallbackV10::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
    const UserIam::UserAuth::Attributes &extraInfo)
{
}

void UserAuthCallbackV10::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", result);
    uv_loop_s *loop;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    ResultCallbackV10Holder *resultHolder = new (std::nothrow) ResultCallbackV10Holder();
    if (resultHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        delete work;
        return;
    }
    resultHolder->callback = shared_from_this();
    resultHolder->result =  UserAuthNapiHelper::GetResultCodeV10(result); // ResultCode -> UserAuthResultCode
    resultHolder->env = env_;
    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, resultHolder->token)) {
        IAM_LOGE("ATTR_SIGNATURE is null");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, resultHolder->authType)) {
        IAM_LOGE("ATTR_AUTH_TYPE is null");
    }
    if (!extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, resultHolder->enrolledState.credentialDigest)) {
        IAM_LOGE("ATTR_CREDENTIAL_DIGEST is null");
    }
    if (!extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, resultHolder->enrolledState.credentialCount)) {
        IAM_LOGE("ATTR_CREDENTIAL_COUNT is null");
    }
    work->data = reinterpret_cast<void *>(resultHolder);
    if (uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {}, OnResultV10Work, uv_qos_user_initiated) != 0) {
        IAM_LOGE("uv_queue_work_with_qos fail");
        DestoryResultWork(work);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
