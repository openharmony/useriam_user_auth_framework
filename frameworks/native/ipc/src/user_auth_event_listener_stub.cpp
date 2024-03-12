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

#include "user_auth_event_listener_stub.h"

#include <cinttypes>

#include "iam_logger.h"
#include "user_auth_interface.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t AuthEventListenerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (AuthEventListenerStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    if (code == UserAuthInterfaceCode::USER_AUTH_EVENT_LISTENER_NOTIFY) {
        return OnNotifyAuthSuccessEventStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AuthEventListenerStub::OnNotifyAuthSuccessEventStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    int32_t userId = 0;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }
    int32_t authType = 0;
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    std::string callerName;
    if (!data.ReadString(callerName)) {
        IAM_LOGE("failed to read callerName");
        return READ_PARCEL_ERROR;
    }
    int32_t callerType = 0;
    if (!data.ReadInt32(callerType)) {
        IAM_LOGE("failed to read callerType");
        return READ_PARCEL_ERROR;
    }
    OnNotifyAuthSuccessEvent(userId, static_cast<AuthType>(authType), callerType, callerName);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS