/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef MOCK_USER_AUTH_CALLBACK_SERVICE_H
#define MOCK_USER_AUTH_CALLBACK_SERVICE_H

#include <gmock/gmock.h>

#include "iam_callback_stub.h"
#include "get_executor_property_callback_stub.h"
#include "set_executor_property_callback_stub.h"
#include "iam_callback_stub.h"
#include "user_auth_event_listener_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserAuthCallbackService final : public IamCallbackStub {
public:
    MOCK_METHOD2(OnResult, int32_t(int32_t resultCode, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, int32_t(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockGetExecutorPropertyCallbackService final : public GetExecutorPropertyCallbackStub {
public:
    MOCK_METHOD2(OnGetExecutorPropertyResult, int32_t(int32_t resultCode, const std::vector<uint8_t> &attributes));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockSetExecutorPropertyCallbackService final : public SetExecutorPropertyCallbackStub {
public:
    MOCK_METHOD1(OnSetExecutorPropertyResult, int32_t(int32_t resultCode));
    MOCK_METHOD1(CallbackEnter, int32_t(uint32_t code));
    MOCK_METHOD2(CallbackExit, int32_t(uint32_t code, int32_t result));
};

class MockAuthEventListenerService final : public AuthEventListenerStub {
public:
    MOCK_METHOD4(OnNotifyAuthSuccessEvent, void(int32_t userId, AuthType authtype, int32_t callerType,
        std::string &callerName));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_USER_AUTH_CALLBACK_SERVICE_H
