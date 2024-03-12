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

#include "user_auth_event_listener_proxy.h"

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "user_auth_interface.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
bool AuthEventListenerProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, result = %{public}d", result);
        return false;
    }
    IAM_LOGI("end");
    return true;
}

void AuthEventListenerProxy::OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
    std::string &callerName)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(AuthEventListenerProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("write userId failed");
        return;
    }
    if (!data.WriteInt32(static_cast<int32_t>(authType))) {
        IAM_LOGE("write authType failed");
        return;
    }
    if (!data.WriteString(callerName)) {
        IAM_LOGE("write callerName failed");
        return;
    }
    if (!data.WriteInt32(callerType)) {
        IAM_LOGE("write callerType failed");
        return;
    }
    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_EVENT_LISTENER_NOTIFY, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
    }
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS