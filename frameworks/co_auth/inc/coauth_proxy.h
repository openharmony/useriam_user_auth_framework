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

#ifndef COAUTH_PROXY_H
#define COAUTH_PROXY_H

#include <iremote_proxy.h>
#include <iremote_broker.h>
#include "i_coauth.h"
#include "attributes.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class CoAuthProxy : public IRemoteProxy<ICoAuth> {
public:
    explicit CoAuthProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<ICoAuth>(impl) {}
    ~CoAuthProxy() override = default;
    uint64_t Register(std::shared_ptr<AuthResPool::AuthExecutor> executorInfo,
        const sptr<AuthResPool::IExecutorCallback> &callback) override;

private:
    static inline BrokerDelegator<CoAuthProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync = true);
    uint32_t WriteAuthExecutor(AuthResPool::AuthExecutor &executorInfo, MessageParcel &data);
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // COAUTH_PROXY_H