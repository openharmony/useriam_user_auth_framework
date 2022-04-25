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

#include "useridm_getsecinfo_callback_proxy.h"
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
void UserIDMGetSecInfoCallbackProxy::OnGetSecInfo(SecInfo &info)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMGetSecInfoCallbackProxy OnGetSecInfo start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMGetSecInfoCallbackProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_SERVICE, "failed to write descriptor");
        return;
    }

    if (!data.WriteUint64(info.secureUid)) {
        USERIDM_HILOGE(MODULE_SERVICE, "failed to WriteUint64(info.secureUid)");
        return;
    }

    if (!data.WriteUint32(info.enrolledInfoLen)) {
        USERIDM_HILOGE(MODULE_SERVICE, "failed to WriteUint32(info.enrolledInfoLen)");
        return;
    }

    bool ret = SendRequest(ON_GET_SEC_INFO, data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        USERIDM_HILOGI(MODULE_SERVICE, "result = %{public}d", result);
    }
}

bool UserIDMGetSecInfoCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMGetSecInfoCallbackProxy SendRequest start");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "failed to get remote");
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
