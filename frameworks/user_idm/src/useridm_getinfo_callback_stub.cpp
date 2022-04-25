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

#include "useridm_getinfo_callback_stub.h"
#include <message_parcel.h>
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
UserIDMGetInfoCallbackStub::UserIDMGetInfoCallbackStub(const std::shared_ptr<GetInfoCallback>& impl)
{
    callback_ = impl;
}

int32_t UserIDMGetInfoCallbackStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMGetInfoCallbackStub::OnRemoteRequest, cmd = %{public}u, flags= %d",
        code, option.GetFlags());

    if (UserIDMGetInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        USERIDM_HILOGE(MODULE_CLIENT,
            "UserIDMGetInfoCallbackStub::OnRemoteRequest failed, descriptor is not matched!");
        return FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IGetInfoCallback::ON_GET_INFO):
            return OnGetInfoStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserIDMGetInfoCallbackStub::OnGetInfoStub(MessageParcel& data, MessageParcel& reply)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMGetInfoCallbackStub OnGetInfoStub start");
    uint32_t vectorSize = 0;
    std::vector<CredentialInfo> credInfos;
    if (!data.ReadUint32(vectorSize)) {
        USERIDM_HILOGE(MODULE_CLIENT, "read size fail");
        OnGetInfo(credInfos);
        return FAIL;
    }
    for (uint32_t i = 0; i < vectorSize; i++) {
        CredentialInfo info;
        if (!data.ReadUint64(info.credentialId)) {
            USERIDM_HILOGE(MODULE_CLIENT, "read credential id fail");
            OnGetInfo(credInfos);
            return FAIL;
        }
        uint32_t authType = 0;
        if (!data.ReadUint32(authType)) {
            USERIDM_HILOGE(MODULE_CLIENT, "read type fail");
            OnGetInfo(credInfos);
            return FAIL;
        }
        info.authType = static_cast<AuthType>(authType);
        uint64_t authSubType = 0;
        if (!data.ReadUint64(authSubType)) {
            USERIDM_HILOGE(MODULE_CLIENT, "read subtype fail");
            OnGetInfo(credInfos);
            return FAIL;
        }
        info.authSubType = static_cast<AuthSubType>(authSubType);
        if (!data.ReadUint64(info.templateId)) {
            USERIDM_HILOGE(MODULE_CLIENT, "read template id fail");
            OnGetInfo(credInfos);
            return FAIL;
        }
        credInfos.push_back(info);
    }
    OnGetInfo(credInfos);
    if (!reply.WriteInt32(SUCCESS)) {
        USERIDM_HILOGE(MODULE_CLIENT, "write result fail");
        return FAIL;
    }
    return SUCCESS;
}

void UserIDMGetInfoCallbackStub::OnGetInfo(std::vector<CredentialInfo>& infos)
{
    USERIDM_HILOGI(MODULE_CLIENT, "UserIDMGetInfoCallbackStub OnGetInfo start");

    if (callback_ == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "UserIDMGetInfoCallbackStub OnGetInfo callback_ is nullptr");
        return;
    }
    if (infos.size() > 0) {
        USERIDM_HILOGI(MODULE_CLIENT, "have data");
    } else {
        USERIDM_HILOGI(MODULE_CLIENT, "get no data");
    }
    // Call the NaPi interface and return the data to JS
    callback_->OnGetInfo(infos);
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
