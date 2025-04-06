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

#include "event_listener_manager.h"

#include <sstream>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using DeathRecipient = IRemoteObject::DeathRecipient;
int32_t EventListenerManager::RegistEventListener(const std::vector<AuthType> &authType, uint32_t tokenId,
    const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int32_t result = AddDeathRecipient(this, tokenId, listener);
    if (result != SUCCESS) {
        IAM_LOGE("AddDeathRecipient fail");
        return result;
    }

    for (const auto &iter : authType) {
        AddEventListener(iter, listener);
    }
    IAM_LOGI("RegistEventListener success, deathRecipientMap size: %{public}zu", deathRecipientMap_.size());
    return SUCCESS;
}

int32_t EventListenerManager::UnRegistEventListener(uint32_t tokenId, const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int32_t result = RemoveDeathRecipient(tokenId);
    if (result != SUCCESS) {
        IAM_LOGE("RemoveDeathRecipient fail");
        return result;
    }

    for (auto authType : AUTH_TYPE_WHITE_SET) {
        RemoveEventListener(authType, listener);
    }
    IAM_LOGI("UnRegistEventListener success, deathRecipientMap size: %{public}zu", deathRecipientMap_.size());
    return SUCCESS;
}

void EventListenerManager::AddEventListener(AuthType authType, const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("AddEventListener, authType:%{public}d", static_cast<int32_t>(authType));
    auto iter = std::find_if(eventListenerMap_[authType].begin(), eventListenerMap_[authType].end(),
        FinderSet(listener->AsObject()));
    if (iter != eventListenerMap_[authType].end()) {
        IAM_LOGE("listener is already registed");
        return;
    }
    eventListenerMap_[authType].insert(listener);
    IAM_LOGI("AddEventListener success");
}

void EventListenerManager::RemoveEventListener(AuthType authType, const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("RemoveEventListener, authType:%{public}d", static_cast<int32_t>(authType));
    auto iter = std::find_if(eventListenerMap_[authType].begin(), eventListenerMap_[authType].end(),
        FinderSet(listener->AsObject()));
    if (iter == eventListenerMap_[authType].end()) {
        IAM_LOGE("listener is not registed");
        return;
    }
    eventListenerMap_[authType].erase(listener);
    IAM_LOGI("RemoveEventListener success");
}

std::set<sptr<IEventListenerCallback>> EventListenerManager::GetListenerSet(AuthType authType)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::set<sptr<IEventListenerCallback>> listenerSet(eventListenerMap_[authType]);
    return listenerSet;
}

int32_t EventListenerManager::AddDeathRecipient(EventListenerManager *manager, uint32_t tokenId,
    const sptr<IEventListenerCallback> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    auto obj = listener->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return GENERAL_ERROR;
    }

    auto iter = deathRecipientMap_.find(tokenId);
    if (iter != deathRecipientMap_.end()) {
        IAM_LOGE("deathRecipient is already registed");
        return SUCCESS;
    }

    sptr<DeathRecipient> dr(new (std::nothrow) EventListenerDeathRecipient(manager));
    if ((dr == nullptr) || (!obj->AddDeathRecipient(dr))) {
        IAM_LOGE("AddDeathRecipient failed");
        return GENERAL_ERROR;
    }

    deathRecipientMap_.emplace(tokenId, std::make_pair(listener, dr));
    IAM_LOGI("AddDeathRecipient success");
    return SUCCESS;
}

int32_t EventListenerManager::RemoveDeathRecipient(uint32_t tokenId)
{
    IAM_LOGI("start");
    auto iter = deathRecipientMap_.find(tokenId);
    if (iter == deathRecipientMap_.end()) {
        IAM_LOGE("deathRecipient is not registed");
        return SUCCESS;
    }

    sptr<DeathRecipient> deathRecipient = iter->second.second;
    IF_FALSE_LOGE_AND_RETURN_VAL(deathRecipient != nullptr, GENERAL_ERROR);
    auto listener = iter->second.first;
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);
    auto obj = listener->AsObject();
    IF_FALSE_LOGE_AND_RETURN_VAL(obj != nullptr, GENERAL_ERROR);

    obj->RemoveDeathRecipient(deathRecipient);
    deathRecipientMap_.erase(tokenId);
    IAM_LOGI("RemoveDeathRecipient success");
    return SUCCESS;
}

DeathRecipientMap EventListenerManager::GetDeathRecipientMap()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return deathRecipientMap_;
}

EventListenerManager::EventListenerDeathRecipient::EventListenerDeathRecipient(EventListenerManager *manager)
    : eventListenerManager_(manager) {}

void EventListenerManager::EventListenerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr || eventListenerManager_ == nullptr) {
        IAM_LOGE("remote or manager is nullptr");
        return;
    }

    auto deathRecipientMap = eventListenerManager_->GetDeathRecipientMap();
    for (auto &iter : deathRecipientMap) {
        if (iter.second.first != nullptr && remote == iter.second.first->AsObject()) {
            int32_t result = eventListenerManager_->UnRegistEventListener(iter.first, iter.second.first);
            if (result != SUCCESS) {
                IAM_LOGE("UnRegistEventListener fail");
                return;
            }
        }
    }
}

AuthEventListenerManager &AuthEventListenerManager::GetInstance()
{
    IAM_LOGI("start");
    static AuthEventListenerManager authEventListenerManager;
    return authEventListenerManager;
}

void AuthEventListenerManager::OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
    const std::string &callerName)
{
    IAM_LOGI("start");
    std::set<sptr<IEventListenerCallback>> listenerSetTemp = GetListenerSet(authType);
    for (auto &iter : listenerSetTemp) {
        if (iter != nullptr) {
            iter->OnNotifyAuthSuccessEvent(userId, authType, callerType, callerName);
        }
    }
}

CredChangeEventListenerManager &CredChangeEventListenerManager::GetInstance()
{
    IAM_LOGI("start");
    static CredChangeEventListenerManager credChangeEventListenerManager;
    return credChangeEventListenerManager;
}

void CredChangeEventListenerManager::OnNotifyCredChangeEvent(int32_t userId, AuthType authType,
    CredChangeEventType eventType, uint64_t credentialId)
{
    IAM_LOGI("start");
    std::set<sptr<IEventListenerCallback>> listenerSetTemp = GetListenerSet(authType);
    for (auto &iter : listenerSetTemp) {
        if (iter != nullptr) {
            iter->OnNotifyCredChangeEvent(userId, authType, eventType, credentialId);
        }
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS