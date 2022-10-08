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

#include "user_auth_callback_stub.h"

#include <cinttypes>

#include "iam_logger.h"
#include "user_auth_interface.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t UserAuthCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (UserAuthCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    switch (code) {
        case UserAuthInterface::USER_AUTH_ON_RESULT:
            return OnResultStub(data, reply);
        case UserAuthInterface::USER_AUTH_ACQUIRE_INFO:
            return OnAcquireInfoStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserAuthCallbackStub::OnResultStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    std::vector<uint8_t> buffer;

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&buffer)) {
        IAM_LOGE("failed to read buffer");
        return READ_PARCEL_ERROR;
    }
    
    Attributes extraInfo(buffer);
    OnResult(result, extraInfo);
    return SUCCESS;
}

int32_t UserAuthCallbackStub::OnAcquireInfoStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t module;
    int32_t acquireInfo;
    std::vector<uint8_t> buffer;

    if (!data.ReadInt32(module)) {
        IAM_LOGE("failed to read module");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(acquireInfo)) {
        IAM_LOGE("failed to read acquireInfo");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&buffer)) {
        IAM_LOGE("failed to read buffer");
        return READ_PARCEL_ERROR;
    }
    
    Attributes extraInfo(buffer);
    OnAcquireInfo(module, acquireInfo, extraInfo);
    return SUCCESS;
}

int32_t GetExecutorPropertyCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (GetExecutorPropertyCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    if (code == UserAuthInterface::USER_AUTH_GET_EX_PROP) {
        return OnGetExecutorPropertyResultStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t GetExecutorPropertyCallbackStub::OnGetExecutorPropertyResultStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    std::vector<uint8_t> buffer;

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&buffer)) {
        IAM_LOGE("failed to read buffer");
        return READ_PARCEL_ERROR;
    }

    Attributes attr(buffer);
    OnGetExecutorPropertyResult(result, attr);
    return SUCCESS;
}

int32_t SetExecutorPropertyCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (SetExecutorPropertyCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    if (code == UserAuthInterface::USER_AUTH_SET_EX_PROP) {
        return OnSetExecutorPropertyResultStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SetExecutorPropertyCallbackStub::OnSetExecutorPropertyResultStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    OnSetExecutorPropertyResult(result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS