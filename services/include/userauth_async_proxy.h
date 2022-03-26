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

#ifndef USERAUTH_ASYNC_PROXY_H
#define USERAUTH_ASYNC_PROXY_H

#include <iremote_proxy.h>
#include "iuserauth_callback.h"
#include "useridm_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuthAsyncProxy : public IRemoteProxy<IUserAuthCallback> {
public:
    DISALLOW_COPY_AND_MOVE(UserAuthAsyncProxy);
    explicit UserAuthAsyncProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IUserAuthCallback>(object)
    {
    }
    ~UserAuthAsyncProxy() override = default;

    void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) override;
    void onResult(const int32_t result, const AuthResult &extraInfo) override;
    void onExecutorPropertyInfo(const ExecutorProperty &result) override;
    void onSetExecutorProperty(const int32_t result) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<UserAuthAsyncProxy> delegator_;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // USERAUTH_ASYNC_PROXY_H
