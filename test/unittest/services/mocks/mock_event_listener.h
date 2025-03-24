/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef IAM_MOCK_EVENT_LISTENER_INTERFACE_H
#define IAM_MOCK_EVENT_LISTENER_INTERFACE_H

#include <gmock/gmock.h>

#include "event_listener_stub.h"
#include "user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockEventListener final : public EventListenerInterface {
public:
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
    MOCK_METHOD4(OnNotifyAuthSuccessEvent, void(int32_t userId, AuthType authType, int32_t callerType,
        std::string &callerName));
    MOCK_METHOD4(OnNotifyCredChangeEvent, void(int32_t userId, AuthType authType, CredChangeEventType eventType,
        uint64_t credentialId));
};

class MockEventListenerService final : public IRemoteStub<EventListenerInterface> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD4(OnNotifyAuthSuccessEvent, void(int32_t userId, AuthType authType, int32_t callerType,
        std::string &callerName));
    MOCK_METHOD4(OnNotifyCredChangeEvent, void(int32_t userId, AuthType authType, CredChangeEventType eventType,
        uint64_t credentialId));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_EVENT_LISTENER_INTERFACE_H