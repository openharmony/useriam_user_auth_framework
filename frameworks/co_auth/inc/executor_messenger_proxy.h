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

#include <iremote_proxy.h>
#include "nocopyable.h"
#include "iexecutor_messenger.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorMessengerProxy : public IRemoteProxy<IExecutorMessenger> {
public:
    explicit ExecutorMessengerProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IExecutorMessenger>(impl) {}
    ~ExecutorMessengerProxy() override = default;

    int32_t SendData(uint64_t scheduleId, uint64_t transNum, int32_t srcType,
        int32_t dstType, std::shared_ptr<AuthMessage> msg) override;
    int32_t Finish(uint64_t scheduleId, int32_t srcType, int32_t resultCode,
        std::shared_ptr<UserIam::UserAuth::Attributes> finalResult) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<ExecutorMessengerProxy> delegator_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
using ExecutorMessengerProxy = OHOS::UserIam::UserAuth::ExecutorMessengerProxy;
}
}
}
#endif  // EXECUTOR_MESSENGER_PROXY_H