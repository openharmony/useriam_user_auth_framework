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

#include "widget_callback_stub.h"

#include <cinttypes>

#include "iam_logger.h"
#include "user_auth_interface.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t WidgetCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (WidgetCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    switch (code) {
        case UserAuthInterfaceCode::USER_AUTH_ON_SEND_COMMAND:
            return OnSendCommandStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t WidgetCallbackStub::OnSendCommandStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    std::string cmdData = data.ReadString();
    SendCommand(cmdData);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS