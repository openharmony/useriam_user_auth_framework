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

#ifndef USER_AUTH_PROXY_H
#define USER_AUTH_PROXY_H

#include "iremote_proxy.h"
#include "message_parcel.h"
#include "nocopyable.h"
#include "user_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthProxy : public IRemoteProxy<UserAuthInterface>, public NoCopyable {
public:
    explicit UserAuthProxy(const sptr<IRemoteObject> &object);
    ~UserAuthProxy() override = default;
    int32_t GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel) override;
    void GetProperty(int32_t userId, AuthType authType,
        const std::vector<Attributes::AttributeKey> &keys,
        sptr<GetExecutorPropertyCallbackInterface> &callback) override;
    void SetProperty(int32_t userId, AuthType authType, const Attributes &attributes,
        sptr<SetExecutorPropertyCallbackInterface> &callback) override;
    uint64_t AuthUser(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback) override;
    uint64_t Auth(int32_t apiVersion, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback) override;
    uint64_t Identify(const std::vector<uint8_t> &challenge, AuthType authType,
        sptr<UserAuthCallbackInterface> &callback) override;
    int32_t CancelAuthOrIdentify(uint64_t contextId) override;
    int32_t GetVersion(int32_t &version) override;

private:
    static inline BrokerDelegator<UserAuthProxy> delegator_;
    bool WriteAuthParam(MessageParcel &data, const std::vector<uint8_t> &challenge,
        AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback);
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_PROXY_H