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

#include "user_auth_callback_v9.h"

#include <uv.h>

#include "iam_logger.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct ResultCallbackV9Holder {
    std::shared_ptr<UserAuthCallbackV9> callback {nullptr};
    int32_t result {0};
    std::vector<uint8_t> token {};
    int32_t remainTimes {0};
    int32_t freezingTime {0};
};

struct AcquireCallbackV9Holder {
    std::shared_ptr<UserAuthCallbackV9> callback {nullptr};
    int32_t module {0};
    uint32_t acquireInfo {0};
};

void DestoryResultWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<ResultCallbackV9Holder *>(work->data));
    }
    delete work;
}

void DestoryAcquireWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<AcquireCallbackV9Holder *>(work->data));
    }
    delete work;
}

void OnResultV9Work(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    ResultCallbackV9Holder *resultHolder = reinterpret_cast<ResultCallbackV9Holder *>(work->data);
    if (resultHolder == nullptr || resultHolder->callback == nullptr) {
        IAM_LOGE("resultHolder is invalid");
        DestoryResultWork(work);
        return;
    }
    napi_status ret = resultHolder->callback->DoResultCallback(resultHolder->result, resultHolder->token,
        resultHolder->remainTimes, resultHolder->freezingTime);
    if (ret != napi_ok) {
        IAM_LOGE("DoResultCallback fail %{public}d", ret);
        DestoryResultWork(work);
        return;
    }
    DestoryResultWork(work);
}

void OnAcquireV9Work(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    AcquireCallbackV9Holder *acquireHolder = reinterpret_cast<AcquireCallbackV9Holder *>(work->data);
    if (acquireHolder == nullptr || acquireHolder->callback == nullptr) {
        IAM_LOGE("acquireHolder is invalid");
        DestoryAcquireWork(work);
        return;
    }
    napi_status ret = acquireHolder->callback->DoAcquireCallback(acquireHolder->module, acquireHolder->acquireInfo);
    if (ret != napi_ok) {
        IAM_LOGE("DoAcquireCallback fail %{public}d", ret);
        DestoryAcquireWork(work);
        return;
    }
    DestoryAcquireWork(work);
}
}

UserAuthCallbackV9::UserAuthCallbackV9(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAuthCallbackV9 get null env");
    }
}

UserAuthCallbackV9::~UserAuthCallbackV9()
{
}

void UserAuthCallbackV9::SetResultCallback(const std::shared_ptr<JsRefHolder> &resultCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = resultCallback;
}

void UserAuthCallbackV9::ClearResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    resultCallback_ = nullptr;
}

void UserAuthCallbackV9::SetAcquireCallback(const std::shared_ptr<JsRefHolder> &acquireCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    acquireCallback_ = acquireCallback;
}

void UserAuthCallbackV9::ClearAcquireCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    acquireCallback_ = nullptr;
}

std::shared_ptr<JsRefHolder> UserAuthCallbackV9::GetResultCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return resultCallback_;
}

std::shared_ptr<JsRefHolder> UserAuthCallbackV9::GetAcquireCallback()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return acquireCallback_;
}

napi_status UserAuthCallbackV9::DoResultCallback(int32_t result,
    const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime)
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
    ret = UserAuthNapiHelper::SetUint8ArrayProperty(env_, eventInfo, "token", token);
    if (ret != napi_ok) {
        IAM_LOGE("SetUint8ArrayProperty failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "remainAttempts", remainTimes);
    if (ret != napi_ok) {
        IAM_LOGE("SetInt32Property failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "lockoutDuration", freezingTime);
    if (ret != napi_ok) {
        IAM_LOGE("SetInt32Property failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, resultCallback->Get(), ARGS_ONE, &eventInfo);
}

napi_status UserAuthCallbackV9::DoAcquireCallback(int32_t module, uint32_t acquireInfo)
{
    auto acquireCallback = GetAcquireCallback();
    if (acquireCallback == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value eventInfo;
    napi_status ret = napi_create_object(env_, &eventInfo);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, eventInfo, "module", module);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetUint32Property(env_, eventInfo, "tip", acquireInfo);
    if (ret != napi_ok) {
        IAM_LOGE("SetUint32Property failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, acquireCallback->Get(), ARGS_ONE, &eventInfo);
}

void UserAuthCallbackV9::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
    const UserIam::UserAuth::Attributes &extraInfo)
{
    IAM_LOGI("start module:%{public}d acquireInfo:%{public}u", module, acquireInfo);
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
    AcquireCallbackV9Holder *acquireHolder = new (std::nothrow) AcquireCallbackV9Holder();
    if (acquireHolder == nullptr) {
        IAM_LOGE("acquireHolder is null");
        delete work;
        return;
    }
    acquireHolder->callback = shared_from_this();
    acquireHolder->module = module;
    acquireHolder->acquireInfo = acquireInfo;
    work->data = reinterpret_cast<void *>(acquireHolder);
    if (uv_queue_work(loop, work, [](uv_work_t *work) {}, OnAcquireV9Work) != 0) {
        IAM_LOGE("uv_queue_work fail");
        DestoryAcquireWork(work);
    }
}

void UserAuthCallbackV9::OnResult(int32_t result, const Attributes &extraInfo)
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
    ResultCallbackV9Holder *resultHolder = new (std::nothrow) ResultCallbackV9Holder();
    if (resultHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        delete work;
        return;
    }
    resultHolder->callback = shared_from_this();
    resultHolder->result = UserAuthNapiHelper::GetResultCodeV9(result);
    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, resultHolder->token)) {
        IAM_LOGE("ATTR_SIGNATURE is null");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, resultHolder->remainTimes)) {
        IAM_LOGE("ATTR_REMAIN_TIMES is null");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_FREEZING_TIME, resultHolder->freezingTime)) {
        IAM_LOGE("ATTR_FREEZING_TIME is null");
    }

    work->data = reinterpret_cast<void *>(resultHolder);
    if (uv_queue_work(loop, work, [](uv_work_t *work) {}, OnResultV9Work) != 0) {
        IAM_LOGE("uv_queue_work fail");
        DestoryResultWork(work);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
