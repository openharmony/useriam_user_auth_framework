/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "user_access_ctrl_callback_service.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_ACCESS_CTRL_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
VerifyTokenCallbackService::VerifyTokenCallbackService(
    const std::shared_ptr<VerifyTokenCallback> &impl) : verifyTokenCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user access ctrl service death, return default verify token result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

VerifyTokenCallbackService::~VerifyTokenCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

void VerifyTokenCallbackService::OnVerifyTokenResult(int32_t result, const Attributes &attributes)
{
    IAM_LOGI("start, verify token result: %{public}d", result);
    if (verifyTokenCallback_ == nullptr) {
        IAM_LOGE("verifyTokenCallback is nullptr");
        return;
    }

    verifyTokenCallback_->OnResult(result, attributes);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS