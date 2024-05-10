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

#include "auth_event_listener_manager.h"

#include <sstream>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using DeathRecipient = IRemoteObject::DeathRecipient;
AuthEventListenerManager &AuthEventListenerManager::GetInstance()
{
    IAM_LOGI("start");
    static AuthEventListenerManager authEventListenerManager;
    return authEventListenerManager;
}

int32_t AuthEventListenerManager::RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
    const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    std::lock_guard<std::mutex> lock(mutex_);
    int32_t result = AddDeathRecipient(listener);
    if (result != SUCCESS) {
        IAM_LOGE("AddDeathRecipient fail");
        return result;
    }

    for (const auto &iter : authType) {
        AddAuthSuccessEventListener(iter, listener);
    }
    IAM_LOGI("RegistUserAuthSuccessEventListener success");
    return SUCCESS;
}

int32_t AuthEventListenerManager::UnRegistUserAuthSuccessEventListener(const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    std::lock_guard<std::mutex> lock(mutex_);
    int32_t result = RemoveDeathRecipient(listener);
    if (result != SUCCESS) {
        IAM_LOGE("RemoveDeathRecipient fail");
        return result;
    }

    RemoveAuthSuccessEventListener(AuthType::PIN, listener);
    RemoveAuthSuccessEventListener(AuthType::FACE, listener);
    RemoveAuthSuccessEventListener(AuthType::FINGERPRINT, listener);
    IAM_LOGI("UnRegistUserAuthSuccessEventListener success");
    return SUCCESS;
}

void AuthEventListenerManager::AddAuthSuccessEventListener(AuthType authType,
    const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGI("AddAuthSuccessEventListener, authType:%{public}d", static_cast<int32_t>(authType));
    auto iter = std::find_if(eventListenerMap_[authType].begin(), eventListenerMap_[authType].end(),
        FinderSet(listener->AsObject()));
    if (iter != eventListenerMap_[authType].end()) {
        IAM_LOGE("listener is already registed");
        return;
    }
    eventListenerMap_[authType].insert(listener);
    IAM_LOGI("AddAuthSuccessEventListener success");
}

void AuthEventListenerManager::RemoveAuthSuccessEventListener(AuthType authType,
    const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGI("RemoveAuthSuccessEventListener, authType:%{public}d", static_cast<int32_t>(authType));
    auto iter = std::find_if(eventListenerMap_[authType].begin(), eventListenerMap_[authType].end(),
        FinderSet(listener->AsObject()));
    if (iter == eventListenerMap_[authType].end()) {
        IAM_LOGE("listener is not registed");
        return;
    }
    eventListenerMap_[authType].erase(listener);
    IAM_LOGI("RemoveAuthSuccessEventListener success");
}

std::set<sptr<AuthEventListenerInterface>> AuthEventListenerManager::GetListenerSet(AuthType authType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<sptr<AuthEventListenerInterface>> listenerSet(eventListenerMap_[authType]);
    return listenerSet;
}

void AuthEventListenerManager::OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
    std::string &callerName)
{
    IAM_LOGI("start");
    std::set<sptr<AuthEventListenerInterface>> listenerSetTemp = GetListenerSet(authType);
    for (auto &iter : listenerSetTemp) {
        if (iter != nullptr) {
            iter->OnNotifyAuthSuccessEvent(userId, authType, callerType, callerName);
            IAM_LOGI("OnNotifyAuthSuccessEvent, userId: %{public}d, authType: %{public}d, callerName: %{public}s, "
                "callerType: %{public}d",
                userId, static_cast<int32_t>(authType), callerName.c_str(), callerType);
        }
    }
}

int32_t AuthEventListenerManager::AddDeathRecipient(const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    auto obj = listener->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return GENERAL_ERROR;
    }

    auto iter = std::find_if(deathRecipientMap_.begin(), deathRecipientMap_.end(), FinderMap(listener->AsObject()));
    if (iter != deathRecipientMap_.end()) {
        IAM_LOGE("deathRecipient is already registed");
        return SUCCESS;
    }

    sptr<DeathRecipient> dr(new (std::nothrow) AuthEventListenerDeathRecipient());
    if ((dr == nullptr) || (!obj->AddDeathRecipient(dr))) {
        IAM_LOGE("AddDeathRecipient failed");
        return GENERAL_ERROR;
    }

    deathRecipientMap_.emplace(listener, dr);
    IAM_LOGI("AddDeathRecipient success");
    return SUCCESS;
}

int32_t AuthEventListenerManager::RemoveDeathRecipient(const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);

    auto obj = listener->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return GENERAL_ERROR;
    }

    auto iter = std::find_if(deathRecipientMap_.begin(), deathRecipientMap_.end(), FinderMap(listener->AsObject()));
    if (iter == deathRecipientMap_.end()) {
        IAM_LOGE("deathRecipient is not registed");
        return SUCCESS;
    }

    sptr<DeathRecipient> deathRecipient = iter->second;
    if (deathRecipient == nullptr) {
        IAM_LOGE("deathRecipient is nullptr");
        return GENERAL_ERROR;
    }

    obj->RemoveDeathRecipient(deathRecipient);
    deathRecipientMap_.erase(listener);
    IAM_LOGI("RemoveDeathRecipient success");
    return SUCCESS;
}

std::map<sptr<AuthEventListenerInterface>, sptr<DeathRecipient>> AuthEventListenerManager::GetDeathRecipientMap()
{
    IAM_LOGI("start");
    return deathRecipientMap_;
}

void AuthEventListenerManager::AuthEventListenerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }

    std::map<sptr<AuthEventListenerInterface>, sptr<DeathRecipient>> deathRecipientMap =
        AuthEventListenerManager::GetInstance().GetDeathRecipientMap();
    for (auto &iter : deathRecipientMap) {
        if (iter.first != nullptr && remote == iter.first->AsObject()) {
            int32_t result = AuthEventListenerManager::GetInstance().UnRegistUserAuthSuccessEventListener(iter.first);
            if (result != SUCCESS) {
                IAM_LOGE("UnRegistUserAuthSuccessEventListener fail");
                return;
            }
        }
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS