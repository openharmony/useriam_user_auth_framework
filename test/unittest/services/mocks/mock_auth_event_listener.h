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
#ifndef IAM_MOCK_AUTH_EVENT_LISTENER_INTERFACE_H
#define IAM_MOCK_AUTH_EVENT_LISTENER_INTERFACE_H

#include <gmock/gmock.h>

#include "user_auth_client_callback.h"
#include "user_auth_event_listener_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockAuthEventListener final : public AuthEventListenerInterface {
public:
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
    MOCK_METHOD4(OnNotifyAuthSuccessEvent, void(int32_t userId, AuthType authtype, int32_t callerType,
        std::string &callerName));
};

class MockAuthEventListenerService final : public IRemoteStub<AuthEventListenerInterface> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD4(OnNotifyAuthSuccessEvent, void(int32_t userId, AuthType authtype, int32_t callerType,
        std::string &callerName));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_AUTH_EVENT_LISTENER_INTERFACE_H