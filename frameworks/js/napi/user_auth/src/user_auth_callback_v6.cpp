/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "user_auth_callback_v6.h"

#include <uv.h>

#include "iam_logger.h"

#include "user_auth_napi_helper.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct ResultCallbackV6Holder {
    std::shared_ptr<UserAuthCallbackV6> callback {nullptr};
    int32_t result {0};
};

const std::map<int32_t, AuthenticationResult> g_result2ExecuteResult = {
    {ResultCode::SUCCESS, AuthenticationResult::SUCCESS},
    {ResultCode::FAIL, AuthenticationResult::COMPARE_FAILURE},
    {ResultCode::GENERAL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::CANCELED, AuthenticationResult::CANCELED},
    {ResultCode::TIMEOUT, AuthenticationResult::TIMEOUT},
    {ResultCode::TYPE_NOT_SUPPORT, AuthenticationResult::NO_SUPPORT},
    {ResultCode::TRUST_LEVEL_NOT_SUPPORT, AuthenticationResult::NO_SUPPORT},
    {ResultCode::BUSY, AuthenticationResult::BUSY},
    {ResultCode::INVALID_PARAMETERS, AuthenticationResult::INVALID_PARAMETERS},
    {ResultCode::LOCKED, AuthenticationResult::LOCKED},
    {ResultCode::NOT_ENROLLED, AuthenticationResult::NOT_ENROLLED},
    {ResultCode::IPC_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::INVALID_CONTEXT_ID, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::WRITE_PARCEL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::READ_PARCEL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::CHECK_PERMISSION_FAILED, AuthenticationResult::GENERAL_ERROR},
};

void DestoryWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<ResultCallbackV6Holder *>(work->data));
    }
    delete work;
}

void OnCallbackV6Work(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    ResultCallbackV6Holder *resultHolder = reinterpret_cast<ResultCallbackV6Holder *>(work->data);
    if (resultHolder == nullptr || resultHolder->callback == nullptr) {
        IAM_LOGE("resultHolder is invalid");
        DestoryWork(work);
        return;
    }
    napi_status ret = resultHolder->callback->DoPromise(resultHolder->result);
    if (ret != napi_ok) {
        IAM_LOGE("DoPromise fail %{public}d", ret);
        DestoryWork(work);
        return;
    }
    ret = resultHolder->callback->DoCallback(resultHolder->result);
    if (ret != napi_ok) {
        IAM_LOGE("DoCallback fail %{public}d", ret);
        DestoryWork(work);
        return;
    }
    DestoryWork(work);
    return;
}
}

UserAuthCallbackV6::UserAuthCallbackV6(napi_env env,
    const std::shared_ptr<JsRefHolder> &callback, napi_deferred promise)
    : env_(env), callback_(callback), promise_(promise)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAuthCallbackV6 get null env");
    }
}

UserAuthCallbackV6::~UserAuthCallbackV6()
{
}

napi_status UserAuthCallbackV6::DoPromise(int32_t result)
{
    if (promise_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value resultVal;
    napi_status ret = napi_create_int32(env_, result, &resultVal);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    if (result == ResultCode::SUCCESS) {
        ret = napi_resolve_deferred(env_, promise_, resultVal);
        if (ret != napi_ok) {
            IAM_LOGE("napi_resolve_deferred failed %{public}d", ret);
        }
    } else {
        ret = napi_reject_deferred(env_, promise_, resultVal);
        if (ret != napi_ok) {
            IAM_LOGE("napi_reject_deferred failed %{public}d", ret);
        }
    }
    return ret;
}

napi_status UserAuthCallbackV6::DoCallback(int32_t result)
{
    if (callback_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value resultVal;
    napi_status ret = napi_create_int32(env_, result, &resultVal);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, callback_->Get(), ARGS_ONE, &resultVal);
}

void UserAuthCallbackV6::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
    const UserIam::UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start module:%{public}d acquireInfo:%{public}u", module, acquireInfo);
}

void UserAuthCallbackV6::OnResult(int32_t result, const Attributes &extraInfo)
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
    ResultCallbackV6Holder *resultHolder = new (std::nothrow) ResultCallbackV6Holder();
    if (resultHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        delete work;
        return;
    }
    resultHolder->callback = shared_from_this();
    auto res = g_result2ExecuteResult.find(result);
    if (res == g_result2ExecuteResult.end()) {
        resultHolder->result = static_cast<int32_t>(ResultCode::GENERAL_ERROR);
        IAM_LOGE("result %{public}d not found, set execute result GENERAL_ERROR", result);
    } else {
        resultHolder->result = static_cast<int32_t>(res->second);
        IAM_LOGI("convert result %{public}d to execute result %{public}d", result, resultHolder->result);
    }
    work->data = reinterpret_cast<void *>(resultHolder);
    if (uv_queue_work(loop, work, [](uv_work_t *work) {}, OnCallbackV6Work) != 0) {
        IAM_LOGE("uv_queue_work fail");
        DestoryWork(work);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
