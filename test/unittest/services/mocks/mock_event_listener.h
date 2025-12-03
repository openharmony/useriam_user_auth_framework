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

#include "event_listener_callback_stub.h"
#include "user_auth_client_callback.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockEventListener final : public IEventListenerCallback {
public:
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
    MOCK_METHOD3(OnNotifyAuthSuccessEvent, int32_t(int32_t userId, int32_t authType,
        const IpcAuthSuccessEventInfo &eventInfo));
    MOCK_METHOD4(OnNotifyCredChangeEvent, int32_t(int32_t userId, int32_t authType, int32_t eventType,
        const IpcCredChangeEventInfo &changeInfo));
};

class MockEventListenerService final : public IRemoteStub<IEventListenerCallback> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD3(OnNotifyAuthSuccessEvent, int32_t(int32_t userId, int32_t authType,
        const IpcAuthSuccessEventInfo &eventInfo));
    MOCK_METHOD4(OnNotifyCredChangeEvent, int32_t(int32_t userId, int32_t authType, int32_t eventType,
        const IpcCredChangeEventInfo &changeInfo));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_EVENT_LISTENER_INTERFACE_H