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

#ifndef MODAL_CALLBACK_PROXY_H
#define MODAL_CALLBACK_PROXY_H

#include <iremote_proxy.h>

#include "modal_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ModalCallbackProxy : public IRemoteProxy<ModalCallbackInterface>, public NoCopyable {
public:
    explicit ModalCallbackProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<ModalCallbackInterface>(object)
    {
    }
    ~ModalCallbackProxy() override = default;
    void SendCommand(uint64_t contextId, const std::string &cmdData) override;

private:
    static inline BrokerDelegator<ModalCallbackProxy> delegator_;
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MODAL_CALLBACK_PROXY_H
