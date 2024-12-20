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

#ifndef USER_IDM_STUB_H
#define USER_IDM_STUB_H

#include "user_idm_interface.h"

#include <iremote_stub.h>
#include <message_parcel.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmStub : public IRemoteStub<UserIdmInterface> {
public:
    UserIdmStub();
    ~UserIdmStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t OpenSessionStub(MessageParcel &data, MessageParcel &reply);
    int32_t CloseSessionStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetCredentialInfoStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetSecInfoStub(MessageParcel &data, MessageParcel &reply);
    int32_t AddCredentialStub(MessageParcel &data, MessageParcel &reply);
    int32_t UpdateCredentialStub(MessageParcel &data, MessageParcel &reply);
    int32_t CancelStub(MessageParcel &data, MessageParcel &reply);
    int32_t EnforceDelUserStub(MessageParcel &data, MessageParcel &reply);
    int32_t DelUserStub(MessageParcel &data, MessageParcel &reply);
    int32_t DelCredentialStub(MessageParcel &data, MessageParcel &reply);
    int32_t ClearRedundancyCredentialStub(MessageParcel &data, MessageParcel &reply);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_STUB_H