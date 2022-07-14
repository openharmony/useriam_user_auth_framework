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

#ifndef USER_IDM_CALLBACK_STUB_H
#define USER_IDM_CALLBACK_STUB_H

// #include "iam_hitrace_helper.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"
#include "user_idm_callback_interface.h"
#include "user_idm_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdmCallbackStub : public IRemoteStub<IdmCallbackInterface>, public NoCopyable {
public:
    explicit IdmCallbackStub(const std::shared_ptr<UserIdmClientCallback> &impl);
    ~IdmCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnResult(int32_t result, const Attributes &reqRet) override;
    void OnAcquireInfo(int32_t module, int32_t acquire, const Attributes &reqRet) override;

private:
    int32_t OnResultStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnAcquireInfoStub(MessageParcel &data, MessageParcel &reply);
    std::shared_ptr<UserIdmClientCallback> idmClientCallback_ {nullptr};
};

class IdmGetCredInfoCallbackStub : public IRemoteStub<IdmGetCredInfoCallbackInterface>, public NoCopyable {
public:
    explicit IdmGetCredInfoCallbackStub(const std::shared_ptr<GetCredentialInfoCallback> &impl);
    ~IdmGetCredInfoCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
        const std::optional<PinSubType> pinSubType) override;

private:
    int32_t OnCredentialInfosStub(MessageParcel &data, MessageParcel &reply);
    std::shared_ptr<GetCredentialInfoCallback> getCredInfoCallback_ {nullptr};
};

class IdmGetSecureUserInfoCallbackStub : public IRemoteStub<IdmGetSecureUserInfoCallbackInterface>, public NoCopyable {
public:
    explicit IdmGetSecureUserInfoCallbackStub(const std::shared_ptr<GetSecUserInfoCallback> &impl);
    ~IdmGetSecureUserInfoCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info) override;

private:
    int32_t OnSecureUserInfoStub(MessageParcel &data, MessageParcel &reply);
    std::shared_ptr<GetSecUserInfoCallback> getSecInfoCallback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_CALLBACK_STUB_H