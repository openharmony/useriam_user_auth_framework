/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "user_idm_callback_stub.h"

#include "iam_logger.h"
#include "user_idm_client_defines.h"

#define LOG_TAG "USER_IDM_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const uint32_t INFO_VECTOR_LENGTH_LIMIT = 100;
} // namespace

int32_t IdmCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }
    
    switch (code) {
        case IdmCallbackInterfaceCode::IDM_CALLBACK_ON_RESULT:
            return OnResultStub(data, reply);
        case IdmCallbackInterfaceCode::IDM_CALLBACK_ON_ACQUIRE_INFO:
            return OnAcquireInfoStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t IdmCallbackStub::OnResultStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
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

int32_t IdmCallbackStub::OnAcquireInfoStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
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

int32_t IdmGetCredInfoCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmGetCredInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    if (code == IdmGetCredInfoCallbackInterfaceCode::ON_GET_INFO) {
        return OnCredentialInfosStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ResultCode IdmGetCredInfoCallbackStub::ReadCredentialInfoList(MessageParcel &data,
    std::vector<CredentialInfo> &credInfoList)
{
    IAM_LOGI("start");
    uint32_t credInfosLen = 0;
    if (!data.ReadUint32(credInfosLen)) {
        IAM_LOGE("read credInfosLen fail");
        return READ_PARCEL_ERROR;
    }
    IAM_LOGI("read cred info vector len: %{public}u", credInfosLen);
    if (credInfosLen > INFO_VECTOR_LENGTH_LIMIT) {
        IAM_LOGE("the cred info vector size exceed limit");
        return GENERAL_ERROR;
    }
    for (uint32_t i = 0; i < credInfosLen; ++i) {
        CredentialInfo info = {};
        int32_t authType;
        int32_t pinType = 0;
        if (!data.ReadUint64(info.credentialId)) {
            IAM_LOGE("failed to read credentialId");
            return READ_PARCEL_ERROR;
        }
        if (!data.ReadInt32(authType)) {
            IAM_LOGE("failed to read authType");
            return READ_PARCEL_ERROR;
        }
        if (!data.ReadInt32(pinType)) {
            IAM_LOGE("failed to read pinSubType");
            return READ_PARCEL_ERROR;
        }
        if (!data.ReadUint64(info.templateId)) {
            IAM_LOGE("failed to read templateId");
            return READ_PARCEL_ERROR;
        }
        info.authType = static_cast<AuthType>(authType);
        info.pinType = static_cast<PinSubType>(pinType);
        credInfoList.push_back(info);
    }
    return SUCCESS;
}

int32_t IdmGetCredInfoCallbackStub::OnCredentialInfosStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    std::vector<CredentialInfo> credInfoList;
    if (ReadCredentialInfoList(data, credInfoList) != SUCCESS) {
        IAM_LOGE("ReadCredentialInfoList fail");
        credInfoList.clear();
    }
    OnCredentialInfos(credInfoList);
    return SUCCESS;
}

int32_t IdmGetSecureUserInfoCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmGetSecureUserInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    if (code == IdmGetSecureUserInfoCallbackInterfaceCode::ON_GET_SEC_INFO) {
        return OnSecureUserInfoStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ResultCode IdmGetSecureUserInfoCallbackStub::ReadSecureUserInfo(MessageParcel &data, SecUserInfo &secUserInfo)
{
    IAM_LOGI("start");
    uint32_t enrolledInfoLen;
    if (!data.ReadUint64(secUserInfo.secureUid)) {
        IAM_LOGE("failed to read secureUid");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(enrolledInfoLen)) {
        IAM_LOGE("failed to read enrolledInfoLen");
        return READ_PARCEL_ERROR;
    }
    IAM_LOGI("read enrolled info vector len: %{public}u", enrolledInfoLen);
    if (enrolledInfoLen > INFO_VECTOR_LENGTH_LIMIT) {
        IAM_LOGE("the enrolled info vector size exceed limit");
        return GENERAL_ERROR;
    }
    secUserInfo.enrolledInfo.resize(enrolledInfoLen);
    for (uint32_t i = 0; i < enrolledInfoLen; ++i) {
        int32_t authType;
        uint64_t enrolledId;
        if (!data.ReadInt32(authType)) {
            IAM_LOGE("failed to read authType");
            return READ_PARCEL_ERROR;
        }
        if (!data.ReadUint64(enrolledId)) {
            IAM_LOGE("failed to read enrolledId");
            return READ_PARCEL_ERROR;
        }
        secUserInfo.enrolledInfo[i] = {static_cast<AuthType>(authType), enrolledId};
    }
    return SUCCESS;
}

int32_t IdmGetSecureUserInfoCallbackStub::OnSecureUserInfoStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    SecUserInfo secUserInfo = {};

    if (ReadSecureUserInfo(data, secUserInfo) != SUCCESS) {
        IAM_LOGE("ReadSecureUserInfo fail");
        secUserInfo.secureUid = 0;
        secUserInfo.enrolledInfo.clear();
    }

    OnSecureUserInfo(secUserInfo);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS