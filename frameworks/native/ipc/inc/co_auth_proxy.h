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

#ifndef CO_AUTH_PROXY_H
#define CO_AUTH_PROXY_H

#include "co_auth_interface.h"
#include "iremote_proxy.h"
#include "message_parcel.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthProxy : public IRemoteProxy<CoAuthInterface>, public NoCopyable {
public:
    explicit CoAuthProxy(const sptr<IRemoteObject> &impl);
    ~CoAuthProxy() override = default;
    uint64_t ExecutorRegister(const ExecutorRegisterInfo &info, sptr<ExecutorCallbackInterface> &callback) override;

private:
    static inline BrokerDelegator<CoAuthProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    int32_t WriteExecutorInfo(const ExecutorRegisterInfo &info, MessageParcel &data);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_PROXY_H