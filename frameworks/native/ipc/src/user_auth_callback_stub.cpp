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

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t UserAuthCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (UserAuthCallbackStub::GetOldDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return FAIL;
    }

    switch (code) {
        case UserAuthInterface::USER_AUTH_ACQUIRE_INFO:
            return OnAcquireInfoStub(data, reply);
        case UserAuthInterface::USER_AUTH_ON_RESULT:
            return OnAuthResultStub(data, reply);
        case UserAuthInterface::USER_AUTH_ON_IDENTIFY_RESULT:
            return OnIdentifyResultStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserAuthCallbackStub::OnAcquireInfoStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t module;
    uint32_t acquireInfo;
    int32_t extraInfo;

    if (!data.ReadInt32(module)) {
        IAM_LOGE("failed to read module");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(acquireInfo)) {
        IAM_LOGE("failed to read acquireInfo");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(extraInfo)) {
        IAM_LOGE("failed to read extraInfo");
        return READ_PARCEL_ERROR;
    }
    
    OnAcquireInfo(module, acquireInfo, extraInfo);
    return SUCCESS;
}

int32_t UserAuthCallbackStub::OnAuthResultStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    std::vector<uint8_t> token;
    int32_t remainTimes = 0;
    int32_t freezingTime = 0;

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&token)) {
        IAM_LOGE("failed to read token");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(remainTimes)) {
        IAM_LOGE("failed to read remain times");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(freezingTime)) {
        IAM_LOGE("failed to read freezing time");
        return READ_PARCEL_ERROR;
    }
    
    Attributes extraInfo;
    if (!extraInfo.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token)) {
        IAM_LOGE("failed to set token");
    }
    if (!extraInfo.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes)) {
        IAM_LOGE("failed to set remain times");
    }
    if (!extraInfo.SetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        IAM_LOGE("failed to set freezing times");
    }
    OnAuthResult(result, extraInfo);
    return SUCCESS;
}

int32_t UserAuthCallbackStub::OnIdentifyResultStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    int32_t userId = 0;
    std::vector<uint8_t> token;

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&token)) {
        IAM_LOGE("failed to read token");
        return READ_PARCEL_ERROR;
    }

    Attributes extraInfo;
    if (!extraInfo.SetInt32Value(Attributes::ATTR_USER_ID, userId)) {
        IAM_LOGE("failed to set userId");
    }
    if (!extraInfo.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token)) {
        IAM_LOGE("failed to set token");
    }
    OnIdentifyResult(result, extraInfo);
    return SUCCESS;
}

int32_t GetExecutorPropertyCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (GetExecutorPropertyCallbackStub::GetOldDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return FAIL;
    }

    if (code == UserAuthInterface::USER_AUTH_GET_EX_PROP) {
        return OnGetExecutorPropertyResultStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t GetExecutorPropertyCallbackStub::OnGetExecutorPropertyResultStub(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    uint64_t authSubType = 0;
    uint32_t remainTimes = 0;
    uint32_t freezingTime = 0;

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint64(authSubType)) {
        IAM_LOGE("failed to read authSubType");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(remainTimes)) {
        IAM_LOGE("failed to read remain times");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(freezingTime)) {
        IAM_LOGE("failed to read freezing time");
        return READ_PARCEL_ERROR;
    }

    Attributes attr;
    if (!attr.SetUint64Value(Attributes::ATTR_PIN_SUB_TYPE, authSubType)) {
        IAM_LOGE("failed to set authSubType");
    }
    if (!attr.SetUint32Value(Attributes::ATTR_REMAIN_TIMES, remainTimes)) {
        IAM_LOGE("failed to set remain times");
    }
    if (!attr.SetUint32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        IAM_LOGE("failed to set freezing time");
    }
    OnGetExecutorPropertyResult(result, attr);
    return SUCCESS;
}

int32_t SetExecutorPropertyCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (SetExecutorPropertyCallbackStub::GetOldDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return FAIL;
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