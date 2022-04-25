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

#ifndef USERIDM_GET_SECINFO_CALLBACK_PROXY_H
#define USERIDM_GET_SECINFO_CALLBACK_PROXY_H

#include <iremote_proxy.h>
#include "iuseridm_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMGetSecInfoCallbackProxy : public IRemoteProxy<IGetSecInfoCallback> {
public:
    explicit UserIDMGetSecInfoCallbackProxy(const sptr<IRemoteObject> &object)
        :IRemoteProxy<IGetSecInfoCallback>(object) {}
    ~UserIDMGetSecInfoCallbackProxy() override = default;

    void OnGetSecInfo(SecInfo &info) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync = true);

private:
    static inline BrokerDelegator<UserIDMGetSecInfoCallbackProxy> delegator_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
#endif // USERIDM_GET_SECINFO_CALLBACK_PROXY_H