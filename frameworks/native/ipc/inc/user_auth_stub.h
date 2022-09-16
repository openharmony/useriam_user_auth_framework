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

#ifndef USER_AUTH_STUB_H
#define USER_AUTH_STUB_H

#include "user_auth_interface.h"

#include <iremote_stub.h>
#include <message_parcel.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthStub : public IRemoteStub<UserAuthInterface> {
public:
    UserAuthStub() = default;
    ~UserAuthStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t GetAvailableStatusStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetPropertyStub(MessageParcel &data, MessageParcel &reply);
    int32_t SetPropertyStub(MessageParcel &data, MessageParcel &reply);
    int32_t AuthStub(MessageParcel &data, MessageParcel &reply);
    int32_t AuthUserStub(MessageParcel &data, MessageParcel &reply);
    int32_t IdentifyStub(MessageParcel &data, MessageParcel &reply);
    int32_t CancelAuthOrIdentifyStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetVersionStub(MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_STUB_H