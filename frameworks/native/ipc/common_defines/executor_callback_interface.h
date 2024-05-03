/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef EXECUTOR_CALLBACK_INTERFACE_H
#define EXECUTOR_CALLBACK_INTERFACE_H

#include <cstdint>

#include "iremote_broker.h"

#include "executor_messenger_interface.h"
#include "executor_callback_interface_ipc_interface_code.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorCallbackInterface : public IRemoteBroker {
public:
    virtual void OnMessengerReady(uint64_t executorIndex, sptr<ExecutorMessengerInterface> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList) = 0;
    virtual int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command) = 0;
    virtual int32_t OnEndExecute(uint64_t scheduleId, const Attributes &command) = 0;
    virtual int32_t OnSetProperty(const Attributes &properties) = 0;
    virtual int32_t OnGetProperty(const Attributes &condition, Attributes &values) = 0;
    virtual int32_t OnSendData(uint64_t scheduleId, const Attributes &data) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIam.AuthResPool.ExecutorCallback");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EXECUTOR_CALLBACK_INTERFACE_H