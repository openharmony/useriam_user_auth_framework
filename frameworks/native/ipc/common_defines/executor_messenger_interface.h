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

#ifndef EXECUTOR_MESSENGER_INTERFACE_H
#define EXECUTOR_MESSENGER_INTERFACE_H

#include "iremote_broker.h"

#include "attributes.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorMessengerInterface : public IRemoteBroker {
public:
    /* Message ID */
    enum : uint32_t {
        CO_AUTH_SEND_DATA = 0,
        CO_AUTH_FINISH,
    };
    virtual int32_t SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
        const std::vector<uint8_t> &msg) = 0;
    virtual int32_t Finish(uint64_t scheduleId, ExecutorRole srcRole, ResultCode resultCode,
        const std::shared_ptr<Attributes> &finalResult) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIam.AuthResPool.IExecutor_Messenger");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EXECUTOR_MESSENGER_INTERFACE_H