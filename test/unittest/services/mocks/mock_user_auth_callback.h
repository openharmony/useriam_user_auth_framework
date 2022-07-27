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
#ifndef IAM_MOCK_USER_AUTH_CALLBACK_H
#define IAM_MOCK_USER_AUTH_CALLBACK_H

#include <gmock/gmock.h>
#include <iremote_stub.h>

#include "user_auth_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserAuthCallback final : public IRemoteStub<UserAuthCallbackInterface> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD2(OnResult, void(int32_t result, const Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, int32_t acquireInfo, const Attributes &extraInfo));
};

class MockGetExecutorPropertyCallback final : public IRemoteStub<GetExecutorPropertyCallbackInterface> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD2(OnGetExecutorPropertyResult, void(int32_t result, const Attributes &attributes));
};

class MockSetExecutorPropertyCallback final : public IRemoteStub<SetExecutorPropertyCallbackInterface> {
public:
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(OnSetExecutorPropertyResult, void(int32_t result));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_AUTH_CALLBACK_H