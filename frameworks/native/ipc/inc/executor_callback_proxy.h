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

#ifndef EXECUTOR_CALLBACK_PROXY_H
#define EXECUTOR_CALLBACK_PROXY_H

#include <iremote_proxy.h>

#include "executor_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorCallbackProxy : public IRemoteProxy<ExecutorCallbackInterface>, public NoCopyable {
public:
    explicit ExecutorCallbackProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ExecutorCallbackInterface>(impl)
    {
    }
    ~ExecutorCallbackProxy() override = default;
    void OnMessengerReady(sptr<ExecutorMessengerInterface> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList) override;
    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command) override;
    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &command) override;
    int32_t OnSetProperty(const Attributes &properties) override;
    int32_t OnGetProperty(const Attributes &condition, Attributes &values) override;
    int32_t OnSendData(uint64_t scheduleId, const Attributes &data) override;

private:
    static inline BrokerDelegator<ExecutorCallbackProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EXECUTOR_CALLBACK_PROXY_H