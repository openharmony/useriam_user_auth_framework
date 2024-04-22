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

#ifndef IAM_AUTH_EVENT_LISTENER_MANAGER_H
#define IAM_AUTH_EVENT_LISTENER_MANAGER_H

#include "user_auth_interface.h"
#include <map>
#include <mutex>
#include <set>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using DeathRecipient = IRemoteObject::DeathRecipient;
class AuthEventListenerManager {
public:
    static AuthEventListenerManager &GetInstance();
    int32_t RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
        const sptr<AuthEventListenerInterface> &listener);
    int32_t UnRegistUserAuthSuccessEventListener(const sptr<AuthEventListenerInterface> &listener);
    void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType, std::string &callerName);
    int32_t AddDeathRecipient(const sptr<AuthEventListenerInterface> &listener);
    int32_t RemoveDeathRecipient(const sptr<AuthEventListenerInterface> &listener);
    std::map<sptr<AuthEventListenerInterface>, sptr<DeathRecipient>> GetDeathRecipientMap();

protected:
    class AuthEventListenerDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        AuthEventListenerDeathRecipient() = default;
        ~AuthEventListenerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };

    AuthEventListenerManager() = default;
    ~AuthEventListenerManager() = default;
    void AddAuthSuccessEventListener(AuthType authType, const sptr<AuthEventListenerInterface> &listener);
    void RemoveAuthSuccessEventListener(AuthType authType, const sptr<AuthEventListenerInterface> &listener);
    std::set<sptr<AuthEventListenerInterface>> GetListenerSet(AuthType authType);
    std::mutex mutex_;
    std::map<AuthType, std::set<sptr<AuthEventListenerInterface>>> eventListenerMap_;
    std::map<sptr<AuthEventListenerInterface>, sptr<DeathRecipient>> deathRecipientMap_;

private:
    struct FinderSet {
        explicit FinderSet(sptr<IRemoteObject> remoteObject) : remoteObject_(remoteObject)
        {
        }
        bool operator()(sptr<AuthEventListenerInterface> listener)
        {
            return listener->AsObject() == remoteObject_;
        }
        sptr<IRemoteObject> remoteObject_;
    };

    struct FinderMap {
        explicit FinderMap(sptr<IRemoteObject> remoteObject) : remoteObject_(remoteObject)
        {
        }
        bool operator()(std::map<sptr<AuthEventListenerInterface>, sptr<DeathRecipient>>::value_type &pair)
        {
            return pair.first->AsObject() == remoteObject_;
        }
        sptr<IRemoteObject> remoteObject_;
    };
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_AUTH_EVENT_LISTENER_MANAGER_H