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

#include "user_auth_callback_v8.h"

#include <uv.h>

#include "iam_logger.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
struct ResultCallbackV8Holder {
    std::shared_ptr<UserAuthCallbackV8> callback {nullptr};
    int32_t result {0};
    std::vector<uint8_t> token {};
    int32_t remainTimes {0};
    int32_t freezingTime {0};
};

struct AcquireCallbackV8Holder {
    std::shared_ptr<UserAuthCallbackV8> callback {nullptr};
    int32_t module {0};
    uint32_t acquireInfo {0};
};

void DestoryResultWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<ResultCallbackV8Holder *>(work->data));
    }
    delete work;
}

void DestoryAcquireWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<AcquireCallbackV8Holder *>(work->data));
    }
    delete work;
}

void OnResultV8Work(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    ResultCallbackV8Holder *resultHolder = reinterpret_cast<ResultCallbackV8Holder *>(work->data);
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

void OnAcquireV8Work(uv_work_t *work, int status)
{
    IAM_LOGI("start");
    if (work == nullptr) {
        IAM_LOGE("work is null");
        return;
    }
    AcquireCallbackV8Holder *acquireHolder = reinterpret_cast<AcquireCallbackV8Holder *>(work->data);
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

UserAuthCallbackV8::UserAuthCallbackV8(napi_env env,
    const std::shared_ptr<JsRefHolder> &resultCallback, const std::shared_ptr<JsRefHolder> &acquireCallback)
    : env_(env), resultCallback_(resultCallback), acquireCallback_(acquireCallback)
{
    if (env_ == nullptr) {
        IAM_LOGE("UserAuthCallbackV8 get null env");
    }
}

UserAuthCallbackV8::~UserAuthCallbackV8()
{
}

napi_status UserAuthCallbackV8::DoResultCallback(int32_t result,
    const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime)
{
    if (resultCallback_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value params[ARGS_TWO] = {nullptr};
    napi_status ret = napi_create_int32(env_, result, &params[PARAM0]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_create_object(env_, &params[PARAM1]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, params[PARAM1], "remainTimes", remainTimes);
    if (ret != napi_ok) {
        IAM_LOGE("SetInt32Property failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetInt32Property(env_, params[PARAM1], "freezingTime", freezingTime);
    if (ret != napi_ok) {
        IAM_LOGE("SetInt32Property failed %{public}d", ret);
        return ret;
    }
    ret = UserAuthNapiHelper::SetUint8ArrayProperty(env_, params[PARAM1], "token", token);
    if (ret != napi_ok) {
        IAM_LOGE("SetUint8ArrayProperty failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, resultCallback_->Get(), ARGS_TWO, params);
}

napi_status UserAuthCallbackV8::DoAcquireCallback(int32_t module, uint32_t acquireInfo)
{
    if (acquireCallback_ == nullptr) {
        return napi_ok;
    }
    IAM_LOGI("start");
    napi_value params[ARGS_TWO];
    napi_status ret = napi_create_int32(env_, module, &params[PARAM0]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_create_uint32(env_, acquireInfo, &params[PARAM1]);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_uint32 failed %{public}d", ret);
        return ret;
    }
    return UserAuthNapiHelper::CallVoidNapiFunc(env_, acquireCallback_->Get(), ARGS_TWO, params);
}

void UserAuthCallbackV8::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
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
    AcquireCallbackV8Holder *acquireHolder = new (std::nothrow) AcquireCallbackV8Holder();
    if (acquireHolder == nullptr) {
        IAM_LOGE("acquireHolder is null");
        delete work;
        return;
    }
    acquireHolder->callback = shared_from_this();
    acquireHolder->module = module;
    acquireHolder->acquireInfo = acquireInfo;
    work->data = reinterpret_cast<void *>(acquireHolder);
    if (uv_queue_work(loop, work, [](uv_work_t *work) {}, OnAcquireV8Work) != 0) {
        IAM_LOGE("uv_queue_work fail");
        DestoryAcquireWork(work);
    }
}

void UserAuthCallbackV8::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", UserAuthNapiHelper::GetResultCodeV8(result));
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
    ResultCallbackV8Holder *resultHolder = new (std::nothrow) ResultCallbackV8Holder();
    if (resultHolder == nullptr) {
        IAM_LOGE("resultHolder is null");
        delete work;
        return;
    }
    resultHolder->callback = shared_from_this();
    resultHolder->result = UserAuthNapiHelper::GetResultCodeV8(result);
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
    if (uv_queue_work(loop, work, [](uv_work_t *work) {}, OnResultV8Work) != 0) {
        IAM_LOGE("uv_queue_work fail");
        DestoryResultWork(work);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
