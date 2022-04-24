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

#ifndef USERIDM_GET_SECINFO_CALLBACK_STUB_H
#define USERIDM_GET_SECINFO_CALLBACK_STUB_H

#include <iremote_stub.h>
#include "iuseridm_callback.h"
#include "useridm_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMGetSecInfoCallbackStub : public IRemoteStub<IGetSecInfoCallback> {
public:
    explicit UserIDMGetSecInfoCallbackStub(const std::shared_ptr<GetSecInfoCallback> &impl);
    ~UserIDMGetSecInfoCallbackStub() override = default;

    void OnGetSecInfo(SecInfo &info) override;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t OnGetSecInfoStub(MessageParcel &data, MessageParcel &reply);

    std::shared_ptr<GetSecInfoCallback> callback_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS

#endif // USERIDM_GET_SECINFO_CALLBACK_STUB_H