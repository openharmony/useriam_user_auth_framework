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
#include "event_listener_stub.h"
#include "user_auth_client_callback.h"
#include "user_idm_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EventListenerCallbackService : public EventListenerStub {
public:
    explicit EventListenerCallbackService(const std::shared_ptr<AuthSuccessEventListener> &impl);
    explicit EventListenerCallbackService(const std::shared_ptr<CredChangeEventListener> &impl);
    ~EventListenerCallbackService() override;

    void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
        std::string &callerName) override;
    void OnNotifyCredChangeEvent(int32_t userId, AuthType authType, CredChangeEventType eventType,
        uint64_t credentialId) override;

private:
    std::shared_ptr<AuthSuccessEventListener> authSuccessEventListener_ {nullptr};
    std::shared_ptr<CredChangeEventListener> credChangeEventListener_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EVENT_LISTENER_CALLBACK_SERVICE_H
