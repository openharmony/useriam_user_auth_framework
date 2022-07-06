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

#ifndef USERAUTH_PROXY_H
#define USERAUTH_PROXY_H

#include <iremote_proxy.h>
#include <nocopyable.h>
#include "iuser_auth.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthProxy : public IRemoteProxy<IUserAuth> {
public:
    DISALLOW_COPY_AND_MOVE(UserAuthProxy);
    explicit UserAuthProxy(const sptr<IRemoteObject> &object);
    ~UserAuthProxy() override = default;

    int32_t GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel) override;
    void GetProperty(const GetPropertyRequest request, sptr<IUserAuthCallback> &callback) override;
    void GetProperty(const int32_t userId, const GetPropertyRequest request,
        sptr<IUserAuthCallback> &callback) override;
    void SetProperty(const SetPropertyRequest request, sptr<IUserAuthCallback> &callback) override;
    uint64_t Auth(const uint64_t challenge, const AuthType authType, const AuthTrustLevel authTrustLevel,
        sptr<IUserAuthCallback> &callback) override;
    uint64_t AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
        const AuthTrustLevel authTrustLevel, sptr<IUserAuthCallback> &callback) override;
    int32_t CancelAuth(const uint64_t contextId) override;
    uint64_t Identify(const uint64_t challenge, const AuthType authType,
        sptr<IUserAuthCallback> &callback) override;
    int32_t CancelIdentify(const uint64_t contextId) override;
    int32_t GetVersion() override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption option);
    static inline BrokerDelegator<UserAuthProxy> delegator_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using UserAuthProxy = OHOS::UserIam::UserAuth::UserAuthProxy;
}
}
}
#endif // USERAUTH_PROXY_H