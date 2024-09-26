/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
    UserAuthStub();
    ~UserAuthStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t GetAvailableStatusStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetPropertyStub(MessageParcel &data, MessageParcel &reply);
    int32_t SetPropertyStub(MessageParcel &data, MessageParcel &reply);
    int32_t AuthStub(MessageParcel &data, MessageParcel &reply);
    int32_t AuthWidgetStub(MessageParcel &data, MessageParcel &reply);
    int32_t AuthUserStub(MessageParcel &data, MessageParcel &reply);
    int32_t IdentifyStub(MessageParcel &data, MessageParcel &reply);
    int32_t CancelAuthOrIdentifyStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetVersionStub(MessageParcel &data, MessageParcel &reply);
    int32_t NoticeStub(MessageParcel &data, MessageParcel &reply);
    bool ReadWidgetParam(MessageParcel &data, AuthParamInner &authParam, WidgetParam &widgetParam);
    int32_t RegisterWidgetCallbackStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetEnrolledStateStub(MessageParcel &data, MessageParcel &reply);
    int32_t RegistUserAuthSuccessEventListenerStub(MessageParcel &data, MessageParcel &reply);
    int32_t UnRegistUserAuthSuccessEventListenerStub(MessageParcel &data, MessageParcel &reply);
    int32_t SetGlobalConfigParamStub(MessageParcel &data, MessageParcel &reply);
    int32_t PrepareRemoteAuthStub(MessageParcel &data, MessageParcel &reply);
    bool ReadAuthParam(MessageParcel &data, AuthParamInner &authParam);
    bool ReadRemoteAuthParam(MessageParcel &data, std::optional<RemoteAuthParam> &remoteAuthParam);
    bool ReadOptionalString(MessageParcel &data, std::optional<std::string> &str);
    bool ReadOptionalUint32(MessageParcel &data, std::optional<uint32_t> &val);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_STUB_H