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

#include "useridm_getsecinfo_callback_stub.h"
#include <message_parcel.h>
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
UserIDMGetSecInfoCallbackStub::UserIDMGetSecInfoCallbackStub(const std::shared_ptr<GetSecInfoCallback>& impl)
{
    callback_ = impl;
}

int32_t UserIDMGetSecInfoCallbackStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    USERIDM_HILOGI(MODULE_CLIENT,
        "UserIDMGetSecInfoCallbackStub::OnRemoteRequest, code:%{public}u, flags:%{public}d", code, option.GetFlags());

    if (UserIDMGetSecInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        USERIDM_HILOGE(MODULE_CLIENT,
            "UserIDMGetSecInfoCallbackStub::OnRemoteRequest failed, descriptor is not matched!");
        return FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IGetSecInfoCallback::ON_GET_SEC_INFO):
            return OnGetSecInfoStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserIDMGetSecInfoCallbackStub::OnGetSecInfoStub(MessageParcel& data, MessageParcel& reply)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMGetSecInfoCallbackStub OnGetSecInfoStub start");

    int32_t ret = SUCCESS;
    SecInfo info = {};
    info.secureUid = data.ReadUint64();
    info.enrolledInfoLen = data.ReadUint32();

    this->OnGetSecInfo(info);
    if (!reply.WriteInt32(ret)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteInt32(ret)");
        ret = FAIL;
    }

    return ret;
}

void UserIDMGetSecInfoCallbackStub::OnGetSecInfo(SecInfo &info)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMGetSecInfoCallbackStub OnGetSecInfo start");

    if (callback_ == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "UserIDMGetSecInfoCallbackStub callback_ is nullptr");
        return;
    } else {
        callback_->OnGetSecInfo(info);
    }
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS