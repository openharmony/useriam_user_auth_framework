/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "user_access_ctrl_callback_proxy.h"

#include "iam_logger.h"
#include "user_access_ctrl_callback_interface.h"

#define LOG_TAG "USER_ACCESS_CTRL_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void VerifyTokenCallbackProxy::OnVerifyTokenResult(int32_t result, const Attributes &attributes)
{
    IAM_LOGI("start, result: %{public}d", result);

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(VerifyTokenCallbackProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("write result failed");
        return;
    }
    auto buffer = attributes.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("write buffer failed");
        return;
    }

    bool ret = SendRequest(UserAccessCtrlCallbackInterfaceCode::ON_VERIFY_TOKEN_RESULT, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}


bool VerifyTokenCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("failed to send request result = %{public}d", result);
        return false;
    }

    IAM_LOGI("end");
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
