/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_EVENT_LISTERNR_PROXY_H
#define USER_AUTH_EVENT_LISTERNR_PROXY_H

#include <iremote_proxy.h>
#include "user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthEventListenerProxy : public IRemoteProxy<AuthEventListenerInterface>, public NoCopyable {
public:
    explicit AuthEventListenerProxy(const sptr<IRemoteObject> &object)
        : IRemoteProxy<AuthEventListenerInterface>(object)
    {
    }
    ~AuthEventListenerProxy() override = default;
    void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
        std::string &callerName) override;

private:
    static inline BrokerDelegator<AuthEventListenerProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_EVENT_LISTERNR_PROXY_H
