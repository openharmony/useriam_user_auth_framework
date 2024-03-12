/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "widget_callback_proxy.h"

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "user_auth_interface.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void WidgetCallbackProxy::SendCommand(const std::string &cmdData)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(WidgetCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteString(cmdData)) {
        IAM_LOGE("write cmd data failed");
        return;
    }
    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_ON_SEND_COMMAND, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
    }
}

bool WidgetCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, result = %{public}d", result);
        return false;
    }
    IAM_LOGI("end");
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS