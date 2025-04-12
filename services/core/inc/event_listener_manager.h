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

#ifndef IAM_EVENT_LISTENER_MANAGER_H
#define IAM_EVENT_LISTENER_MANAGER_H

#include "iuser_auth.h"
#include "iuser_idm.h"
#include "user_idm_client_defines.h"
#include "event_listener_callback_stub.h"
#include <map>
#include <mutex>
#include <set>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EventListenerManager {
public:
    EventListenerManager() = default;
    ~EventListenerManager() = default;
    int32_t RegistEventListener(const std::vector<AuthType> &authType, const sptr<IEventListenerCallback> &listener);
    int32_t UnRegistEventListener(const sptr<IEventListenerCallback> &listener);
    int32_t AddDeathRecipient(EventListenerManager *manager, const sptr<IEventListenerCallback> &listener);
    int32_t RemoveDeathRecipient(const sptr<IEventListenerCallback> &listener);
    std::map<sptr<IEventListenerCallback>, sptr<DeathRecipient>> GetDeathRecipientMap();

protected:
    class EventListenerDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        EventListenerDeathRecipient(EventListenerManager *manager);
        ~EventListenerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        EventListenerManager *eventListenerManager_;
    };

    void AddEventListener(AuthType authType, const sptr<IEventListenerCallback> &listener);
    void RemoveEventListener(AuthType authType, const sptr<IEventListenerCallback> &listener);
    std::set<sptr<IEventListenerCallback>> GetListenerSet(AuthType authType);
    std::recursive_mutex mutex_;
    std::map<AuthType, std::set<sptr<IEventListenerCallback>>> eventListenerMap_;
    std::map<sptr<IEventListenerCallback>, sptr<DeathRecipient>> deathRecipientMap_;

private:
    struct FinderSet {
        explicit FinderSet(sptr<IRemoteObject> remoteObject) : remoteObject_(remoteObject)
        {
        }
        bool operator()(sptr<IEventListenerCallback> listener)
        {
            return listener->AsObject() == remoteObject_;
        }
        sptr<IRemoteObject> remoteObject_ {nullptr};
    };
    struct FinderMap {
        explicit FinderMap(sptr<IRemoteObject> remoteObject) : remoteObject_(remoteObject)
        {
        }
        bool operator()(std::map<sptr<IEventListenerCallback>, sptr<DeathRecipient>>::value_type &pair)
        {
            return pair.first->AsObject() == remoteObject_;
        }
        sptr<IRemoteObject> remoteObject_ {nullptr};
    };
};

class AuthEventListenerManager : public EventListenerManager {
public:
    static AuthEventListenerManager &GetInstance();
    void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
        const std::string &callerName);
};

class CredChangeEventListenerManager : public EventListenerManager {
public:
    static CredChangeEventListenerManager &GetInstance();
    void OnNotifyCredChangeEvent(int32_t userId, AuthType authType, CredChangeEventType eventType,
        uint64_t credentialId);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_EVENT_LISTENER_MANAGER_H