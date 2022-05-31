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

#ifndef USERIDM_PROXY_H
#define USERIDM_PROXY_H

#include <iremote_proxy.h>
#include "iuser_idm.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMProxy : public IRemoteProxy<IUserIDM> {
public:
    explicit UserIDMProxy(const sptr<IRemoteObject> &object)
        :IRemoteProxy<IUserIDM>(object) {}
    ~UserIDMProxy() override = default;

    uint64_t OpenSession() override;
    uint64_t OpenSession(const int32_t userId) override;
    void CloseSession() override;
    void CloseSession(const int32_t userId) override;
    int32_t GetAuthInfo(const AuthType authType, const sptr<IGetInfoCallback> &callback) override;
    int32_t GetAuthInfo(const int32_t userId, const AuthType authType, const sptr<IGetInfoCallback> &callback) override;
    int32_t GetSecInfo(const int32_t userId, const sptr<IGetSecInfoCallback> &callback) override;
    void AddCredential(const AddCredInfo &credInfo, const sptr<IIDMCallback> &callback) override;
    void AddCredential(const int32_t userId, const AddCredInfo &credInfo, const sptr<IIDMCallback> &callback) override;
    void UpdateCredential(const AddCredInfo &credInfo, const sptr<IIDMCallback> &callback) override;
    void UpdateCredential(const int32_t userId, const AddCredInfo &credInfo,
        const sptr<IIDMCallback> &callback) override;
    int32_t Cancel(const uint64_t challenge) override;
    int32_t Cancel(const int32_t userId) override;
    int32_t EnforceDelUser(const int32_t userId, const sptr<IIDMCallback> &callback) override;
    void DelUser(const std::vector<uint8_t> authToken, const sptr<IIDMCallback> &callback) override;
    void DelUser(const int32_t userId, const std::vector<uint8_t> authToken,
        const sptr<IIDMCallback> &callback) override;
    void DelCred(const uint64_t credentialId, const std::vector<uint8_t> authToken,
        const sptr<IIDMCallback> &callback) override;
    void DelCredential(const int32_t userId, const uint64_t credentialId, const std::vector<uint8_t> authToken,
        const sptr<IIDMCallback> &callback) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync = true);

private:
    static inline BrokerDelegator<UserIDMProxy> delegator_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS


#endif // USERIDM_PROXY_H
