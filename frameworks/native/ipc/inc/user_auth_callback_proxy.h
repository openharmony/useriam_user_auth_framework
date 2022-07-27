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

#ifndef USER_AUTH_CALLBACK_PROXY_H
#define USER_AUTH_CALLBACK_PROXY_H

#include <iremote_proxy.h>

#include "user_auth_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthCallbackProxy : public IRemoteProxy<UserAuthCallbackInterface>, public NoCopyable {
public:
    explicit UserAuthCallbackProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<UserAuthCallbackInterface>(object)
    {
    }
    ~UserAuthCallbackProxy() override = default;
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo) override;

private:
    static inline BrokerDelegator<UserAuthCallbackProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};

class GetExecutorPropertyCallbackProxy : public IRemoteProxy<GetExecutorPropertyCallbackInterface>, public NoCopyable {
public:
    explicit GetExecutorPropertyCallbackProxy(const sptr<IRemoteObject> &object)
        : IRemoteProxy<GetExecutorPropertyCallbackInterface>(object)
    {
    }
    ~GetExecutorPropertyCallbackProxy() override = default;
    void OnGetExecutorPropertyResult(int32_t result, const Attributes &attributes) override;

private:
    static inline BrokerDelegator<GetExecutorPropertyCallbackProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};

class SetExecutorPropertyCallbackProxy : public IRemoteProxy<SetExecutorPropertyCallbackInterface>, public NoCopyable {
public:
    explicit SetExecutorPropertyCallbackProxy(const sptr<IRemoteObject> &object)
        : IRemoteProxy<SetExecutorPropertyCallbackInterface>(object)
    {
    }
    ~SetExecutorPropertyCallbackProxy() override = default;
    void OnSetExecutorPropertyResult(int32_t result) override;

private:
    static inline BrokerDelegator<SetExecutorPropertyCallbackProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CALLBACK_PROXY_H
