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

#ifndef USER_AUTH_ASYNC_PROXY_H
#define USER_AUTH_ASYNC_PROXY_H

#include <iremote_proxy.h>

#include "user_auth_callback_interface.h"
#include "user_idm_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdmCallbackProxy : public IRemoteProxy<IdmCallbackInterface>, public NoCopyable {
public:
    explicit IdmCallbackProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IdmCallbackInterface>(object)
    {
    }
    ~IdmCallbackProxy() override = default;
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<IdmCallbackProxy> delegator_;
};

class IdmGetCredentialInfoProxy : public IRemoteProxy<IdmGetCredInfoCallbackInterface>, public NoCopyable {
public:
    explicit IdmGetCredentialInfoProxy(const sptr<IRemoteObject> &object)
        : IRemoteProxy<IdmGetCredInfoCallbackInterface>(object)
    {
    }
    ~IdmGetCredentialInfoProxy() override = default;
    void OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
        const std::optional<PinSubType> pinSubType) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<IdmGetCredentialInfoProxy> delegator_;
};

class IdmGetSecureUserInfoProxy : public IRemoteProxy<IdmGetSecureUserInfoCallbackInterface>, public NoCopyable {
public:
    explicit IdmGetSecureUserInfoProxy(const sptr<IRemoteObject> &object)
        : IRemoteProxy<IdmGetSecureUserInfoCallbackInterface>(object)
    {
    }
    ~IdmGetSecureUserInfoProxy() override = default;
    void OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<IdmGetSecureUserInfoProxy> delegator_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_ASYNC_PROXY_H
