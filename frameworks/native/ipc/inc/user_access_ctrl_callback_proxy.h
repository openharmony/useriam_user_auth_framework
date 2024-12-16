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

#ifndef USER_ACCESS_CTRL_CALLBACK_PROXY_H
#define USER_ACCESS_CTRL_CALLBACK_PROXY_H

#include <iremote_proxy.h>

#include "user_access_ctrl_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class VerifyTokenCallbackProxy : public IRemoteProxy<VerifyTokenCallbackInterface>, public NoCopyable {
public:
    explicit VerifyTokenCallbackProxy(const sptr<IRemoteObject> &object)
        : IRemoteProxy<VerifyTokenCallbackInterface>(object)
    {
    }
    ~VerifyTokenCallbackProxy() override = default;
    void OnVerifyTokenResult(int32_t result, const Attributes &attributes) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<VerifyTokenCallbackProxy> delegator_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_CALLBACK_PROXY_H
