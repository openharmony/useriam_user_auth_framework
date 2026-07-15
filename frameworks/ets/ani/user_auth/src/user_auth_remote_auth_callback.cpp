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

#include "iam_logger.h"
#include "iam_ptr.h"
#include "attributes.h"
#include "user_auth_modal_callback.h"
#include "user_auth_param_utils.h"
#include "user_auth_helper.h"
#include "user_auth_ani_helper.h"

#define LOG_TAG "USER_AUTH_ANI"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_REMOTE_AUTH_CALLBACK_ANI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
RemoteAuthCallback::RemoteAuthCallback(const userAuth::IRemoteAuthCallback &callback)
{
    callback_ = Common::MakeShared<userAuth::IRemoteAuthCallback>(callback);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
    }
}

RemoteAuthCallback::~RemoteAuthCallback()
{}

bool RemoteAuthCallback::DoGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
    userAuth::WidgetParam &widgetParam)
{
    IAM_LOGI("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return false;
    }

    taihe::array<uint8_t> challengeArray =
        taihe::array<uint8_t>(taihe::copy_data_t{}, challenge.data(), challenge.size());
    widgetParam = callback_->onGetRemoteAuthWidgetParam(challengeArray);
    return true;
}

bool RemoteAuthCallback::DoRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t resultCode,
    const Attributes &extraInfo)
{
    IAM_LOGI("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return false;
    }
    taihe::array<uint8_t> challengeArray =
        taihe::array<uint8_t>(taihe::copy_data_t{}, challenge.data(), challenge.size());
    userAuth::UserAuthResult userAuthResult = {};
    UserAuthResultCode ret = UserAuthParamUtils::GetUserAuthResult(resultCode, extraInfo, userAuthResult);
    if (ret != UserAuthResultCode::SUCCESS) {
        IAM_LOGE("GetUserAuthResult failed %{public}d", ret);
        return false;
    }
    callback_->onRemoteAuthResult(challengeArray, userAuthResult);
    return true;
}

void RemoteAuthCallback::OnGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
    const std::shared_ptr<SetWidgetParamClientCallback> &callback)
{
    IAM_LOGI("start");
    if (callback_ == nullptr) {
        IAM_LOGE("callback is null");
        return;
    }

    userAuth::WidgetParam widgetParam = {};
    if (!DoGetRemoteAuthWidgetParam(challenge, widgetParam)) {
        IAM_LOGE("DoGetRemoteAuthWidgetParam failed");
        return;
    }

    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    sptr<OHOS::Rosen::Window> window = nullptr;
    std::shared_ptr<UserAuthModalCallback> modalCallback = nullptr;
    SetWidgetParamClientCallback::WidgetParamExt widgetParamExt = {};
    UserAuthParamUtils::InitWidgetParam(widgetParam, widgetParamExt, context, window);
    if (context == nullptr && window != nullptr) {
        modalCallback = Common::MakeShared<UserAuthModalCallback>(window);
    } else {
        modalCallback = Common::MakeShared<UserAuthModalCallback>(context);
    }
    int32_t ret = callback->OnSetRemoteAuthWidgetParam(widgetParamExt, modalCallback);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("OnSetRemoteAuthWidgetParam failed %{public}d", ret);
        return;
    }
}

void RemoteAuthCallback::OnRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t resultCode,
    const Attributes &extraInfo)
{
    IAM_LOGI("start");
    bool ret = DoRemoteAuthResult(challenge, resultCode, extraInfo);
    if (!ret) {
        IAM_LOGE("DoRemoteAuthResult failed");
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

