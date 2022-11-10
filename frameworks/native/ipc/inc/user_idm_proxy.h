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

#ifndef USER_IDM_PROXY_H
#define USER_IDM_PROXY_H

#include "iremote_proxy.h"
#include "message_parcel.h"
#include "nocopyable.h"
#include "user_idm_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmProxy : public IRemoteProxy<UserIdmInterface>, public NoCopyable {
public:
    explicit UserIdmProxy(const sptr<IRemoteObject> &object);
    ~UserIdmProxy() override = default;
    int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge) override;
    void CloseSession(int32_t userId) override;
    int32_t GetCredentialInfo(int32_t userId, AuthType authType,
        const sptr<IdmGetCredInfoCallbackInterface> &callback) override;
    int32_t GetSecInfo(int32_t userId, const sptr<IdmGetSecureUserInfoCallbackInterface> &callback) override;
    void AddCredential(int32_t userId, const CredentialPara &credPara,
        const sptr<IdmCallbackInterface> &callback, bool isUpdate) override;
    void UpdateCredential(int32_t userId, const CredentialPara &credPara,
        const sptr<IdmCallbackInterface> &callback) override;
    int32_t Cancel(int32_t userId) override;
    int32_t EnforceDelUser(int32_t userId, const sptr<IdmCallbackInterface> &callback) override;
    void DelUser(int32_t userId, const std::vector<uint8_t> authToken,
        const sptr<IdmCallbackInterface> &callback) override;
    void DelCredential(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t> &authToken, const sptr<IdmCallbackInterface> &callback) override;

private:
    static inline BrokerDelegator<UserIdmProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_PROXY_H