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

#ifndef EXECUTOR_CALLBACK_STUB_H
#define EXECUTOR_CALLBACK_STUB_H

#include "executor_callback_interface.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ExecutorCallbackStub : public IRemoteStub<ExecutorCallbackInterface>, public NoCopyable {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t OnMessengerReadyStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnBeginExecuteStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnEndExecuteStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnSetPropertyStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetPropertyStub(MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // EXECUTOR_CALLBACK_STUB_H