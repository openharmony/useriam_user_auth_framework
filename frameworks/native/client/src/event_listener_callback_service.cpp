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
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t EventListenerCallbackManager::AddUserAuthSuccessEventListener(const sptr<IUserAuth> &proxy,
    const std::vector<AuthType> &authTypes, const std::shared_ptr<AuthSuccessEventListener> &listener)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    if (authEventListenerMap_.size() == 0) {
        authEventListenerCallbackImpl_ = new (std::nothrow) EventListenerCallbackImpl();
        IF_FALSE_LOGE_AND_RETURN_VAL(authEventListenerCallbackImpl_ != nullptr, GENERAL_ERROR);
        auto ret = proxy->RegistUserAuthSuccessEventListener(authEventListenerCallbackImpl_);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret == SUCCESS, ret);
    }

    for (auto authType : authTypes) {
        auto addCount = authEventListenerMap_[authType].insert(listener);
        IAM_LOGI("AddEventListener addCount:%{public}d, authType:%{public}d, listenerSize:%{public}zu",
            addCount.second, static_cast<int32_t>(authType), authEventListenerMap_[authType].size());
    }
    return SUCCESS;
}

int32_t EventListenerCallbackManager::RemoveUserAuthSuccessEventListener(const sptr<IUserAuth> &proxy,
    const std::shared_ptr<AuthSuccessEventListener> &listener)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    auto mapIter = authEventListenerMap_.begin();
    while (mapIter != authEventListenerMap_.end()) {
        int32_t eraseCount = mapIter->second.erase(listener);
        IAM_LOGI("RemoveEventListener eraseCount:%{public}d, authType:%{public}d, listenerSize:%{public}zu",
            eraseCount, mapIter->first, mapIter->second.size());
        if (mapIter->second.size() == 0) {
            mapIter = authEventListenerMap_.erase(mapIter);
        } else {
            mapIter++;
        }
    }

    if (authEventListenerMap_.size() == 0) {
        auto ret = proxy->UnRegistUserAuthSuccessEventListener(authEventListenerCallbackImpl_);
        authEventListenerCallbackImpl_ = nullptr;
        return ret;
    }
    return SUCCESS;
}

int32_t EventListenerCallbackManager::AddCredChangeEventListener(const sptr<IUserIdm> &proxy,
    const std::vector<AuthType> &authTypes, const std::shared_ptr<CredChangeEventListener> &listener)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    if (credEventListenerMap_.size() == 0) {
        credEventListenerCallbackImpl_ = new (std::nothrow) EventListenerCallbackImpl();
        IF_FALSE_LOGE_AND_RETURN_VAL(credEventListenerCallbackImpl_ != nullptr, GENERAL_ERROR);
        auto ret = proxy->RegistCredChangeEventListener(credEventListenerCallbackImpl_);
        IF_FALSE_LOGE_AND_RETURN_VAL(ret == SUCCESS, ret);
    }

    for (auto authType : authTypes) {
        auto addCount = credEventListenerMap_[authType].insert(listener);
        IAM_LOGI("AddEventListener addCount:%{public}d, authType:%{public}d, listenerSize:%{public}zu",
            addCount.second, static_cast<int32_t>(authType), credEventListenerMap_[authType].size());
    }
    return SUCCESS;
}

int32_t EventListenerCallbackManager::RemoveCredChangeEventListener(const sptr<IUserIdm> &proxy,
    const std::shared_ptr<CredChangeEventListener> &listener)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    auto mapIter = credEventListenerMap_.begin();
    while (mapIter != credEventListenerMap_.end()) {
        int32_t eraseCount = mapIter->second.erase(listener);
        IAM_LOGI("RemoveEventListener eraseCount:%{public}d, authType:%{public}d, listenerSize:%{public}zu",
            eraseCount, mapIter->first, mapIter->second.size());
        if (mapIter->second.size() == 0) {
            mapIter = credEventListenerMap_.erase(mapIter);
        } else {
            mapIter++;
        }
    }

    if (credEventListenerMap_.size() == 0) {
        auto ret = proxy->UnRegistCredChangeEventListener(credEventListenerCallbackImpl_);
        credEventListenerCallbackImpl_ = nullptr;
        return ret;
    }
    return SUCCESS;
}

std::set<std::shared_ptr<AuthSuccessEventListener>> EventListenerCallbackManager::GetAuthEventListenerSet(
    AuthType authType)
{
    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    if (authEventListenerMap_.find(authType) != authEventListenerMap_.end()) {
        return authEventListenerMap_[authType];
    }
    return {};
}

std::set<std::shared_ptr<CredChangeEventListener>> EventListenerCallbackManager::GetCredEventListenerSet(
    AuthType authType)
{
    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    if (credEventListenerMap_.find(authType) != credEventListenerMap_.end()) {
        return credEventListenerMap_[authType];
    }
    return {};
}

void EventListenerCallbackManager::OnServiceDeath()
{
    IAM_LOGI("userauthservice death, clear caller map and register again");
    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    authEventListenerMap_.clear();
    credEventListenerMap_.clear();
}

EventListenerCallbackManager &EventListenerCallbackManager::GetInstance()
{
    static EventListenerCallbackManager eventListenerCallbackManager;
    return eventListenerCallbackManager;
}

int32_t EventListenerCallbackManager::EventListenerCallbackImpl::OnNotifyAuthSuccessEvent(int32_t userId,
    int32_t authType, int32_t callerType, const std::string &callerName)
{
    IAM_LOGI("OnNotifyAuthSuccessEvent, userId:%{public}d, authType:%{public}d, callerName:%{public}s,"
        "callerType:%{public}d", userId, authType, callerName.c_str(), callerType);
    auto eventListenerSet =
        EventListenerCallbackManager::GetInstance().GetAuthEventListenerSet(static_cast<AuthType>(authType));
    for (const auto &listener : eventListenerSet) {
        if (listener == nullptr) {
            IAM_LOGE("authListener is nullptr");
            continue;
        }
        listener->OnNotifyAuthSuccessEvent(userId, static_cast<AuthType>(authType), callerType, callerName);
    }
    return SUCCESS;
}

int32_t EventListenerCallbackManager::EventListenerCallbackImpl::OnNotifyCredChangeEvent(int32_t userId,
    int32_t authType, int32_t eventType, uint64_t credentialId)
{
    IAM_LOGI("OnNotifyCredChangeEvent, userId:%{public}d, authType:%{public}d, eventType:%{public}d,"
        "credentialId:%{public}u", userId, authType, eventType, static_cast<uint16_t>(credentialId));
    auto eventListenerSet =
        EventListenerCallbackManager::GetInstance().GetCredEventListenerSet(static_cast<AuthType>(authType));
    for (const auto &listener : eventListenerSet) {
        if (listener == nullptr) {
            IAM_LOGE("credListener is nullptr");
            continue;
        }
        listener->OnNotifyCredChangeEvent(userId, static_cast<AuthType>(authType),
            static_cast<CredChangeEventType>(eventType), credentialId);
    }
    return SUCCESS;
}

int32_t EventListenerCallbackManager::EventListenerCallbackImpl::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t EventListenerCallbackManager::EventListenerCallbackImpl::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS