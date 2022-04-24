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

#ifndef USERIDM_CALLBACK_PROXY_H
#define USERIDM_CALLBACK_PROXY_H

#include <iremote_proxy.h>
#include "iuseridm_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMCallbackProxy : public IRemoteProxy<IIDMCallback> {
public:
    explicit UserIDMCallbackProxy(const sptr<IRemoteObject> &object)
        :IRemoteProxy<IIDMCallback>(object) {}
    ~UserIDMCallbackProxy() override = default;

    void OnResult(int32_t result, RequestResult reqRet) override;
    void OnAcquireInfo(int32_t module, int32_t acquire, RequestResult reqRet) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync = true);

    static inline BrokerDelegator<UserIDMCallbackProxy> delegator_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
#endif // USERIDM_CALLBACK_PROXY_H