/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "event_listener_callback_service.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
EventListenerCallbackService::EventListenerCallbackService(
    const std::shared_ptr<AuthSuccessEventListener> &impl) : authSuccessEventListener_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("auth success event listener service death, return default result to caller");
            int32_t invalidCallerType = -1;
            std::string invalidCallerName = "";
            impl->OnNotifyAuthSuccessEvent(INVALID_USER_ID, INVALID_AUTH_TYPE, invalidCallerType
                invalidCallerName);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

EventListenerCallbackService::EventListenerCallbackService(
    const std::shared_ptr<CredChangeEventListener> &impl) : credChangeEventListener_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("cred change event listener service death, return default result to caller");
            uint64_t invalidCredentialId = 0;
            impl->OnNotifyCredChangeEvent(INVALID_USER_ID, INVALID_AUTH_TYPE, INVALID_EVENT_TYPE,
                invalidCredentialId);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

EventListenerCallbackService::~EventListenerCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t EventListenerCallbackService::OnNotifyAuthSuccessEvent(int32_t userId, int32_t authType, int32_t callerType,
    const std::string &callerName)
{
    IAM_LOGI("start, userId:%{public}d, authType:%{public}d, callerName:%{public}s, callerType:%{public}d",
        userId, authType, callerName.c_str(), callerType);
    if (authSuccessEventListener_ == nullptr) {
        IAM_LOGE("authSuccessEventListener_ is null");
        return GENERAL_ERROR;
    }
    authSuccessEventListener_->OnNotifyAuthSuccessEvent(userId, static_cast<AuthType>(authType), callerType,
        callerName);
    return SUCCESS;
}

int32_t EventListenerCallbackService::OnNotifyCredChangeEvent(int32_t userId, int32_t authType, int32_t eventType,
    uint64_t credentialId)
{
    IAM_LOGI("start, userId:%{public}d, authType:%{public}d, eventType:%{public}d, credentialId:%{public}u",
        userId, authType, eventType, static_cast<uint16_t>(credentialId));
    if (credChangeEventListener_ == nullptr) {
        IAM_LOGE("credChangeEventListener_ is null");
        return GENERAL_ERROR;
    }
    credChangeEventListener_->OnNotifyCredChangeEvent(userId, static_cast<AuthType>(authType),
        static_cast<CredChangeEventType>(eventType), credentialId);
    return SUCCESS;
}

int32_t EventListenerCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t EventListenerCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS