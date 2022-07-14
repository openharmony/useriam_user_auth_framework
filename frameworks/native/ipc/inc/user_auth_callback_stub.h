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

#ifndef USER_AUTH_CALLBACK_STUB_H
#define USER_AUTH_CALLBACK_STUB_H

// #include "iam_hitrace_helper.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"
#include "user_auth_callback_interface.h"
#include "user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthCallbackStub : public IRemoteStub<UserAuthCallbackInterface>, public NoCopyable {
public:
    explicit UserAuthCallbackStub(const std::shared_ptr<AuthenticationCallback> &impl);
    explicit UserAuthCallbackStub(const std::shared_ptr<IdentificationCallback> &impl);
    ~UserAuthCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, int32_t extraInfo) override;
    void OnAuthResult(int32_t result, const Attributes &extraInfo) override;
    void OnIdentifyResult(int32_t result, const Attributes &extraInfo) override;

private:
    int32_t OnAcquireInfoStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnAuthResultStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnIdentifyResultStub(MessageParcel &data, MessageParcel &reply);
    std::shared_ptr<AuthenticationCallback> authCallback_ {nullptr};
    std::shared_ptr<IdentificationCallback> identifyCallback_ {nullptr};
};

class GetExecutorPropertyCallbackStub : public IRemoteStub<GetExecutorPropertyCallbackInterface>, public NoCopyable {
public:
    explicit GetExecutorPropertyCallbackStub(const std::shared_ptr<GetPropCallback> &impl);
    ~GetExecutorPropertyCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnGetExecutorPropertyResult(int32_t result, const Attributes &attributes) override;

private:
    int32_t OnGetExecutorPropertyResultStub(MessageParcel &data, MessageParcel &reply);
    std::shared_ptr<GetPropCallback> getPropCallback_ {nullptr};
};

class SetExecutorPropertyCallbackStub : public IRemoteStub<SetExecutorPropertyCallbackInterface>, public NoCopyable {
public:
    explicit SetExecutorPropertyCallbackStub(const std::shared_ptr<SetPropCallback> &impl);
    ~SetExecutorPropertyCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnSetExecutorPropertyResult(int32_t result) override;

private:
    int32_t OnSetExecutorPropertyResultStub(MessageParcel &data, MessageParcel &reply);
    std::shared_ptr<SetPropCallback> setPropCallback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CALLBACK_STUB_H