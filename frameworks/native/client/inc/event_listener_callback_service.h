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
#include "user_auth_client_callback.h"
#include "user_idm_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EventListenerCallbackService : public EventListenerCallbackStub {
public:
    static sptr<EventListenerCallbackService> GetInstance();

    int32_t OnNotifyAuthSuccessEvent(int32_t userId, int32_t authType, int32_t callerType,
        const std::string &callerName) override;
    int32_t OnNotifyCredChangeEvent(int32_t userId, int32_t authType, int32_t eventType,
        const IpcCredChangeEventInfo &changeInfo) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    EventListenerCallbackService() = default;
    ~EventListenerCallbackService() override = default;
};

template<typename T>
class EventListenerCallbackManager {
public:
    static EventListenerCallbackManager<T> &GetInstance();

    int32_t RegisterListener(const std::vector<AuthType> &authTypes, const std::shared_ptr<T> &listener);
    int32_t UnRegisterListener(const std::shared_ptr<T> &listener);
    int32_t RegisterListenerDispatcher(sptr<IRemoteObject> proxy, sptr<EventListenerCallbackService> listenerImpl);
    int32_t UnRegisterListenerDispatcher(sptr<IRemoteObject> proxy, sptr<EventListenerCallbackService> listenerImpl);
    std::set<std::shared_ptr<T>> GetEventListenerSet(AuthType authType);
    bool IsExistEventListener();

private:
    EventListenerCallbackManager();
    ~EventListenerCallbackManager() = default;

    std::recursive_mutex eventListenerMutex_;
    std::map<AuthType, std::set<std::shared_ptr<T>>> eventListenerMap_ = {};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EVENT_LISTENER_CALLBACK_SERVICE_H
