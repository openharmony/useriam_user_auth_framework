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

#include "user_idm_callback_stub.h"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "sec_user_info_impl.h"
#include "user_idm_client_defines.h"
#include "cred_info_impl.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const uint32_t CRED_INFO_VECTOR_LENGTH_LIMIT = 100;
} // namespace

int32_t IdmCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }
    
    switch (code) {
        case IdmCallbackInterface::IDM_CALLBACK_ON_RESULT:
            return OnResultStub(data, reply);
        case IdmCallbackInterface::IDM_CALLBACK_ON_ACQUIRE_INFO:
            return OnAcquireInfoStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t IdmCallbackStub::OnResultStub(MessageParcel &data, MessageParcel &reply)
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

int32_t IdmCallbackStub::OnAcquireInfoStub(MessageParcel &data, MessageParcel &reply)
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

int32_t IdmGetCredInfoCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmGetCredInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    if (code == IdmGetCredInfoCallbackInterface::ON_GET_INFO) {
        return OnCredentialInfosStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t IdmGetCredInfoCallbackStub::OnCredentialInfosStub(MessageParcel &data, MessageParcel &reply)
{
    uint32_t vectorSize = 0;
    std::vector<std::shared_ptr<IdmGetCredInfoCallbackInterface::CredentialInfo>> infoList;
    if (!data.ReadUint32(vectorSize)) {
        IAM_LOGE("read size fail");
        OnCredentialInfos(infoList, std::nullopt);
        return READ_PARCEL_ERROR;
    }
    if (vectorSize > CRED_INFO_VECTOR_LENGTH_LIMIT) {
        IAM_LOGI("the cred info vector size is invalid");
        return GENERAL_ERROR;
    }
    int32_t pinType = 0;
    for (uint32_t i = 0; i < vectorSize; ++i) {
        uint64_t credentialId;
        uint64_t templateId;
        int32_t authType;
        if (!data.ReadUint64(credentialId)) {
            IAM_LOGE("failed to read credentialId");
            OnCredentialInfos(infoList, std::nullopt);
            return READ_PARCEL_ERROR;
        }
        if (!data.ReadInt32(authType)) {
            IAM_LOGE("failed to read authType");
            OnCredentialInfos(infoList, std::nullopt);
            return READ_PARCEL_ERROR;
        }
        if (!data.ReadInt32(pinType)) {
            IAM_LOGE("failed to read pinSubType");
            OnCredentialInfos(infoList, std::nullopt);
            return READ_PARCEL_ERROR;
        }
        if (!data.ReadUint64(templateId)) {
            IAM_LOGE("failed to read templateId");
            OnCredentialInfos(infoList, std::nullopt);
            return READ_PARCEL_ERROR;
        }
        auto credInfo = Common::MakeShared<CredInfoImpl>(credentialId, templateId,
            static_cast<AuthType>(authType));
        infoList.push_back(credInfo);
    }

    std::optional<PinSubType> pinSubType = std::nullopt;
    if (pinType != 0) {
        pinSubType = static_cast<PinSubType>(pinType);
    }
    OnCredentialInfos(infoList, pinSubType);
    return SUCCESS;
}

int32_t IdmGetSecureUserInfoCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmGetSecureUserInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }

    if (code == IdmGetSecureUserInfoCallbackInterface::ON_GET_SEC_INFO) {
        return OnSecureUserInfoStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t IdmGetSecureUserInfoCallbackStub::OnSecureUserInfoStub(MessageParcel &data, MessageParcel &reply)
{
    uint64_t secureUid;
    uint32_t enrolledInfoLen;

    if (!data.ReadUint64(secureUid)) {
        IAM_LOGE("failed to read secureUid");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(enrolledInfoLen)) {
        IAM_LOGE("failed to read enrolledInfoLen");
        return READ_PARCEL_ERROR;
    }

    std::vector<std::shared_ptr<SecEnrolledInfo>> info;
    auto secUserInfo = Common::MakeShared<SecUserInfoImpl>(secureUid, info);
    OnSecureUserInfo(secUserInfo);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS