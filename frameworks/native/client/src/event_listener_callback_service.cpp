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
#include "iservice_registry.h"
#include "ipc_client_utils.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
template<typename L>
EventListenerCallbackManager<L>::EventListenerCallbackManager()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    IF_FALSE_LOGE_AND_RETURN(sam != nullptr);
    auto listener = new(std::nothrow)IamServiceListener();
    IF_FALSE_LOGE_AND_RETURN(listener != nullptr);
    int32_t ret = sam->SubscribeSystemAbility(SystemAbilityByTemplate<L>::systemAbilityId, listener);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to suscribe iam service status, ret:%{public}d", ret);
    }
}

template<typename L>
int32_t EventListenerCallbackManager<L>::RegisterListener(RegisterService registFunc,
    const std::vector<AuthType> &authTypes, const std::shared_ptr<L> &listener)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    if (!IsExistEventListener()) {
        auto listenerImpl = EventListenerCallbackImpl::GetInstance();
        int32_t ret = registFunc(listenerImpl);
        if (ret != SUCCESS) {
            IAM_LOGE("regist listener to service fail:%{public}d", ret);
            return ret;
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
        for (auto authType : authTypes) {
            auto addCount = eventListenerMap_[authType].insert(listener);
            IAM_LOGI("AddEventListener addCount:%{public}d, authType:%{public}d, listenerSize:%{public}zu",
                addCount.second, static_cast<int32_t>(authType), eventListenerMap_[authType].size());
        }
    }
    return SUCCESS;
}

template<typename L>
int32_t EventListenerCallbackManager<L>::UnRegisterListener(UnRegisterService unRegistFunc,
    const std::shared_ptr<L> &listener)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    {
        std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
        auto mapIter = eventListenerMap_.begin();
        while (mapIter != eventListenerMap_.end()) {
            size_t eraseCount = mapIter->second.erase(listener);
            IAM_LOGI("RemoveEventListener eraseCount:%{public}zu, authType:%{public}d, listenerSize:%{public}zu",
                eraseCount, mapIter->first, mapIter->second.size());
            if (mapIter->second.size() == 0) {
                mapIter = eventListenerMap_.erase(mapIter);
            } else {
                mapIter++;
            }
        }
    }

    if (!IsExistEventListener()) {
        auto listenerImpl = EventListenerCallbackImpl::GetInstance();
        return unRegistFunc(listenerImpl);
    }
    return SUCCESS;
}

template<typename L>
std::set<std::shared_ptr<L>> EventListenerCallbackManager<L>::GetEventListenerSet(AuthType authType)
{
    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    if (eventListenerMap_.find(authType) != eventListenerMap_.end()) {
        return eventListenerMap_[authType];
    }
    return {};
}

template<typename L>
bool EventListenerCallbackManager<L>::IsExistEventListener()
{
    std::lock_guard<std::recursive_mutex> lock(eventListenerMutex_);
    return eventListenerMap_.size() != 0;
}

template<typename L>
EventListenerCallbackManager<L> &EventListenerCallbackManager<L>::GetInstance()
{
    static EventListenerCallbackManager<L> eventListenerCallbackManager;
    return eventListenerCallbackManager;
}

template<typename L>
void EventListenerCallbackManager<L>::IamServiceListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    if (systemAbilityId != SystemAbilityByTemplate<L>::systemAbilityId) {
        return;
    }
    IAM_LOGI("OnAddSystemAbility systemAbilityId:%{public}d added", systemAbilityId);

    if (!EventListenerCallbackManager<L>::GetInstance().IsExistEventListener()) {
        IAM_LOGI("not exist eventListner, no need regist");
        return;
    }

    auto proxy = IpcClientUtils::GetRemoteObject(systemAbilityId);
    IF_FALSE_LOGE_AND_RETURN(proxy != nullptr);
    IF_FALSE_LOGE_AND_RETURN(proxy->IsProxyObject());

    int32_t ret = GENERAL_ERROR;
    auto listenerImpl = EventListenerCallbackImpl::GetInstance();
    if constexpr(std::is_same_v<L, AuthSuccessEventListener>) {
        ret = iface_cast<IUserAuth>(proxy)->RegistUserAuthSuccessEventListener(listenerImpl);
    } else if constexpr(std::is_same_v<L, CredChangeEventListener>) {
        ret = iface_cast<IUserIdm>(proxy)->RegistCredChangeEventListener(listenerImpl);
    }
    if (ret != SUCCESS) {
        IAM_LOGE("fail to try re-regist, systemAbilityId:%{public}d, ret:%{public}d", ret, systemAbilityId);
    }
}

template<typename L>
void EventListenerCallbackManager<L>::IamServiceListener::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string &deviceId)
{
    if (systemAbilityId != SystemAbilityByTemplate<L>::systemAbilityId) {
        return;
    }
    IAM_LOGI("OnRemoveSystemAbility systemAbilityId:%{public}d remove", systemAbilityId);
}

template<typename L>
int32_t EventListenerCallbackManager<L>::EventListenerCallbackImpl::OnNotifyAuthSuccessEvent(int32_t userId,
    int32_t authType, int32_t callerType, const std::string &callerName)
{
    IAM_LOGI("OnNotifyAuthSuccessEvent, userId:%{public}d, authType:%{public}d, callerName:%{public}s,"
        "callerType:%{public}d", userId, authType, callerName.c_str(), callerType);

    auto eventListenerSet = EventListenerCallbackManager<AuthSuccessEventListener>::GetInstance().GetEventListenerSet(
        static_cast<AuthType>(authType));
    for (const auto &listener : eventListenerSet) {
        if (listener == nullptr) {
            IAM_LOGE("authListener is nullptr");
            continue;
        }
        listener->OnNotifyAuthSuccessEvent(userId, static_cast<AuthType>(authType), callerType, callerName);
    }
    return SUCCESS;
}

template<typename L>
int32_t EventListenerCallbackManager<L>::EventListenerCallbackImpl::OnNotifyCredChangeEvent(int32_t userId,
    int32_t authType, int32_t eventType, const IpcCredChangeEventInfo &changeInfo)
{
    IAM_LOGI("OnNotifyCredChangeEvent, userId:%{public}d, authType:%{public}d, eventType:%{public}d,"
        "callerName:%{public}s, credId:%{public}u, lastCredId:%{public}u, isSilentCredChange:%{public}u",
        userId, authType, eventType, changeInfo.callerName.c_str(), static_cast<uint16_t>(changeInfo.credentialId),
        static_cast<uint16_t>(changeInfo.lastCredentialId), changeInfo.isSilentCredChange);

    auto eventListenerSet = EventListenerCallbackManager<CredChangeEventListener>::GetInstance().GetEventListenerSet(
        static_cast<AuthType>(authType));
    for (const auto &listener : eventListenerSet) {
        if (listener == nullptr) {
            IAM_LOGE("credListener is nullptr");
            continue;
        }
        listener->OnNotifyCredChangeEvent(userId, static_cast<AuthType>(authType),
            static_cast<CredChangeEventType>(eventType), {changeInfo.callerName, changeInfo.callerType,
            changeInfo.credentialId, changeInfo.lastCredentialId, changeInfo.isSilentCredChange});
    }
    return SUCCESS;
}

template<typename L>
sptr<typename EventListenerCallbackManager<L>::
    EventListenerCallbackImpl> EventListenerCallbackManager<L>::EventListenerCallbackImpl::GetInstance()
{
    auto instance = new (std::nothrow) EventListenerCallbackImpl();
    if (instance == nullptr) {
        IAM_LOGE("instance is nullptr");
    }
    return instance;
}

template<typename L>
int32_t EventListenerCallbackManager<L>::EventListenerCallbackImpl::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

template<typename L>
int32_t EventListenerCallbackManager<L>::EventListenerCallbackImpl::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}

template class EventListenerCallbackManager<CredChangeEventListener>;
template class EventListenerCallbackManager<AuthSuccessEventListener>;
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS