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
    void CloseSession() override;
    int32_t GetAuthInfo(AuthType authType, const sptr<IGetInfoCallback> &callback) override;
    int32_t GetAuthInfo(int32_t userId, AuthType authType, const sptr<IGetInfoCallback> &callback) override;
    int32_t GetSecInfo(int32_t userId, const sptr<IGetSecInfoCallback> &callback) override;
    void AddCredential(AddCredInfo &credInfo, const sptr<IIDMCallback> &callback) override;
    void UpdateCredential(AddCredInfo &credInfo, const sptr<IIDMCallback> &callback) override;
    int32_t Cancel(uint64_t challenge) override;
    int32_t EnforceDelUser(int32_t userId, const sptr<IIDMCallback> &callback) override;
    void DelUser(std::vector<uint8_t> authToken, const sptr<IIDMCallback> &callback) override;
    void DelCred(uint64_t credentialId, std::vector<uint8_t> authToken, const sptr<IIDMCallback> &callback) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync = true);

private:
    static inline BrokerDelegator<UserIDMProxy> delegator_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS


#endif // USERIDM_PROXY_H
