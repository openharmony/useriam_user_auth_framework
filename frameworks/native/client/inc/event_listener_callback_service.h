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

#ifndef EVENT_LISTENER_CALLBACK_SERVICE_H
#define EVENT_LISTENER_CALLBACK_SERVICE_H

#include <string>
#include <map>
#include <set>

#include "event_listener_callback_stub.h"
#include "iuser_auth.h"
#include "iuser_idm.h"
#include "system_ability_status_change_stub.h"
#include "system_ability_definition.h"
#include "user_auth_client_callback.h"
#include "user_idm_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using RegisterService = std::function<int32_t(const sptr<IEventListenerCallback>&)>;
using UnRegisterService = std::function<int32_t(const sptr<IEventListenerCallback>&)>;
template<typename L>
struct SystemAbilityByTemplate { static constexpr int32_t systemAbilityId = 0; };
template<> struct SystemAbilityByTemplate<CredChangeEventListener> {
    static constexpr int32_t systemAbilityId = SUBSYS_USERIAM_SYS_ABILITY_USERIDM;
};
template<> struct SystemAbilityByTemplate<AuthSuccessEventListener> {
    static constexpr int32_t systemAbilityId = SUBSYS_USERIAM_SYS_ABILITY_USERAUTH;
};

template<typename L>
class EventListenerCallbackManager {
public:
    static EventListenerCallbackManager<L> &GetInstance();
    int32_t RegisterListener(RegisterService registFunc, const std::vector<AuthType> &authTypes,
        const std::shared_ptr<L> &listener);
    int32_t UnRegisterListener(UnRegisterService unRegistFunc, const std::shared_ptr<L> &listener);
    std::set<std::shared_ptr<L>> GetEventListenerSet(AuthType authType);

private:
    class EventListenerCallbackImpl : public EventListenerCallbackStub {
    public:
        static sptr<EventListenerCallbackImpl> GetInstance();
        int32_t OnNotifyAuthSuccessEvent(int32_t userId, int32_t authType, int32_t callerType,
            const std::string &callerName) override;
        int32_t OnNotifyCredChangeEvent(int32_t userId, int32_t authType, int32_t eventType,
            const IpcCredChangeEventInfo &changeInfo) override;
        int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
        int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

    private:
        explicit EventListenerCallbackImpl() = default;
        ~EventListenerCallbackImpl() override = default;
    };
    class IamServiceListener : public SystemAbilityStatusChangeStub {
        public:
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
        IamServiceListener() = default;
        ~IamServiceListener() override = default;
    };
    friend class IamServiceListener;

    explicit EventListenerCallbackManager();
    ~EventListenerCallbackManager() = default;
    bool IsExistEventListener();

    std::recursive_mutex eventListenerMutex_;
    std::map<AuthType, std::set<std::shared_ptr<L>>> eventListenerMap_ = {};
};
extern template class EventListenerCallbackManager<CredChangeEventListener>;
extern template class EventListenerCallbackManager<AuthSuccessEventListener>;
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EVENT_LISTENER_CALLBACK_SERVICE_H
