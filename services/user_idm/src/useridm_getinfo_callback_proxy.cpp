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

#include "useridm_getinfo_callback_proxy.h"
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
void UserIDMGetInfoCallbackProxy::OnGetInfo(std::vector<CredentialInfo>& credInfos)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMGetInfoCallbackProxy OnGetInfo start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMGetInfoCallbackProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_SERVICE, "failed to write descriptor");
        return;
    }
    if (!data.WriteUint32(credInfos.size())) {
        USERIDM_HILOGE(MODULE_SERVICE, "failed to WriteUint32(credInfos.size())");
        return;
    }
    if (credInfos.size() > 0) {
        for (uint32_t i = 0; i < credInfos.size(); i++) {
            if (!data.WriteUint64(credInfos[i].credentialId)) {
                USERIDM_HILOGE(MODULE_SERVICE, "failed to WriteUint64(info.credentialId)");
                return;
            }
            if (!data.WriteUint32(credInfos[i].authType)) {
                USERIDM_HILOGE(MODULE_SERVICE, "failed to WriteUint32(info.authType)");
                return;
            }
            if (!data.WriteUint64(credInfos[i].authSubType)) {
                USERIDM_HILOGE(MODULE_SERVICE, "failed to WriteUint64(info.authSubType)");
                return;
            }
            if (!data.WriteUint64(credInfos[i].templateId)) {
                USERIDM_HILOGE(MODULE_SERVICE, "failed to WriteUint64(info.templateId)");
                return;
            }
        }
    }
    bool ret = SendRequest(ON_GET_INFO, data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        USERIDM_HILOGI(MODULE_SERVICE, "result = %{public}d", result);
    }
}

bool UserIDMGetInfoCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMGetInfoCallbackProxy SendRequest start");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "failed to get remote.");
        return false;
    }

    MessageOption option(MessageOption::TF_SYNC);
    if (!isSync) {
        option.SetFlags(MessageOption::TF_ASYNC);
    }

    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::UserIAM::UserIDM::SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "failed to SendRequest.result = %{public}d", result);
        return false;
    }
    return true;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
