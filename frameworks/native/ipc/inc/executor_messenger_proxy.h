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

#ifndef EXECUTOR_MESSENGER_PROXY_H
#define EXECUTOR_MESSENGER_PROXY_H

#include "executor_messenger_interface.h"
#include "iremote_proxy.h"
#include "message_parcel.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorMessengerProxy : public IRemoteProxy<ExecutorMessengerInterface>, public NoCopyable {
public:
    explicit ExecutorMessengerProxy(const sptr<IRemoteObject> &impl);
    ~ExecutorMessengerProxy() override = default;
    int32_t SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
        const std::vector<uint8_t> &msg) override;
    int32_t Finish(uint64_t scheduleId, ExecutorRole srcRole, ResultCode resultCode,
        const std::shared_ptr<Attributes> &finalResult) override;

private:
    static inline BrokerDelegator<ExecutorMessengerProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif  // EXECUTOR_MESSENGER_PROXY_H