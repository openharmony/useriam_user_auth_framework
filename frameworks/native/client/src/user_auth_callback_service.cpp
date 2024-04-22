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

#include "user_auth_callback_service.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserAuthCallbackService::UserAuthCallbackService(const std::shared_ptr<AuthenticationCallback> &impl)
    : authCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, auth callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

UserAuthCallbackService::UserAuthCallbackService(const std::shared_ptr<IdentificationCallback> &impl)
    : identifyCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, identify callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

UserAuthCallbackService::UserAuthCallbackService(const std::shared_ptr<PrepareRemoteAuthCallback> &impl)
    : prepareRemoteAuthCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, prepare remote auth callback return default result to caller");
            impl->OnResult(GENERAL_ERROR);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

UserAuthCallbackService::~UserAuthCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

void UserAuthCallbackService::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", result);
    if (authCallback_ != nullptr) {
        authCallback_->OnResult(result, extraInfo);
    } else if (identifyCallback_ != nullptr) {
        identifyCallback_->OnResult(result, extraInfo);
    } else if (prepareRemoteAuthCallback_ != nullptr) {
        prepareRemoteAuthCallback_->OnResult(result);
    } else {
        IAM_LOGE("all callback is nullptr");
        return;
    }
    iamHitraceHelper_= nullptr;
}

void UserAuthCallbackService::OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo)
{
    IAM_LOGI("start, module:%{public}d acquireInfo:%{public}d", module, acquireInfo);
    if (authCallback_ != nullptr) {
        authCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
    } else if (identifyCallback_ != nullptr) {
        identifyCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
    } else if (prepareRemoteAuthCallback_ != nullptr) {
        IAM_LOGE("prepare remote auth callback not support acquire info");
    } else {
        IAM_LOGE("all callback is nullptr");
        return;
    }
}

GetExecutorPropertyCallbackService::GetExecutorPropertyCallbackService(const std::shared_ptr<GetPropCallback> &impl)
    : getPropCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, get prop callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

GetExecutorPropertyCallbackService::~GetExecutorPropertyCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

void GetExecutorPropertyCallbackService::OnGetExecutorPropertyResult(int32_t result, const Attributes &attributes)
{
    IAM_LOGI("start, result:%{public}d", result);
    if (getPropCallback_ == nullptr) {
        IAM_LOGE("get prop callback is nullptr");
        return;
    }
    getPropCallback_->OnResult(result, attributes);
}

SetExecutorPropertyCallbackService::SetExecutorPropertyCallbackService(const std::shared_ptr<SetPropCallback> &impl)
    : setPropCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user auth service death, set prop callback return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

SetExecutorPropertyCallbackService::~SetExecutorPropertyCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

void SetExecutorPropertyCallbackService::OnSetExecutorPropertyResult(int32_t result)
{
    IAM_LOGI("start, result:%{public}d", result);
    if (setPropCallback_ == nullptr) {
        IAM_LOGE("set prop callback is nullptr");
        return;
    }
    Attributes attr;
    setPropCallback_->OnResult(result, attr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS