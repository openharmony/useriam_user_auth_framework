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

#define LOG_LABEL UserIAM::Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
IdmCallbackStub::IdmCallbackStub(const std::shared_ptr<UserIdmClientCallback> &impl) : idmClientCallback_(impl)
{
}

int32_t IdmCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return FAIL;
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

void IdmCallbackStub::OnResult(int32_t result, const Attributes &reqRet)
{
    if (idmClientCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return;
    }
    idmClientCallback_->OnResult(result, reqRet);
}

void IdmCallbackStub::OnAcquireInfo(int32_t module, int32_t acquire, const Attributes &reqRet)
{
    if (idmClientCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return;
    }
    idmClientCallback_->OnAcquireInfo(module, static_cast<uint32_t>(acquire), reqRet);
}

IdmGetCredInfoCallbackStub::IdmGetCredInfoCallbackStub(
    const std::shared_ptr<GetCredentialInfoCallback> &impl) : getCredInfoCallback_(impl)
{
}

int32_t IdmGetCredInfoCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmGetCredInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return FAIL;
    }

    if (code == IdmGetCredInfoCallbackInterface::ON_GET_INFO) {
        return OnCredentialInfosStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t IdmGetCredInfoCallbackStub::OnCredentialInfosStub(MessageParcel &data, MessageParcel &reply)
{
    if (getCredInfoCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return FAIL;
    }
    uint32_t vectorSize = 0;
    std::vector<UserAuth::CredentialInfo> credInfos;
    if (!data.ReadUint32(vectorSize)) {
        IAM_LOGE("read size fail");
        getCredInfoCallback_->OnCredentialInfo(credInfos);
        return READ_PARCEL_ERROR;
    }
    for (uint32_t i = 0; i < vectorSize; ++i) {
        UserAuth::CredentialInfo info = {};
        if (!data.ReadUint64(info.credentialId)) {
            IAM_LOGE("failed to read credentialId");
            getCredInfoCallback_->OnCredentialInfo(credInfos);
            return READ_PARCEL_ERROR;
        }
        uint32_t authType = 0;
        if (!data.ReadUint32(authType)) {
            IAM_LOGE("failed to read authType");
            getCredInfoCallback_->OnCredentialInfo(credInfos);
            return READ_PARCEL_ERROR;
        }
        info.authType = static_cast<AuthType>(authType);
        uint64_t pinSubType = 0;
        if (!data.ReadUint64(pinSubType)) {
            IAM_LOGE("failed to read pinSubType");
            getCredInfoCallback_->OnCredentialInfo(credInfos);
            return READ_PARCEL_ERROR;
        }
        info.pinType = static_cast<PinSubType>(pinSubType);
        if (!data.ReadUint64(info.templateId)) {
            IAM_LOGE("failed to read templateId");
            getCredInfoCallback_->OnCredentialInfo(credInfos);
            return READ_PARCEL_ERROR;
        }
        credInfos.push_back(info);
    }

    getCredInfoCallback_->OnCredentialInfo(credInfos);
    return SUCCESS;
}

void IdmGetCredInfoCallbackStub::OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
    const std::optional<PinSubType> pinSubType)
{
    return;
}

IdmGetSecureUserInfoCallbackStub::IdmGetSecureUserInfoCallbackStub(const std::shared_ptr<GetSecUserInfoCallback> &impl)
    : getSecInfoCallback_(impl)
{
}

int32_t IdmGetSecureUserInfoCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (IdmGetSecureUserInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return FAIL;
}

    if (code == IdmGetSecureUserInfoCallbackInterface::ON_GET_SEC_INFO) {
        return OnSecureUserInfoStub(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t IdmGetSecureUserInfoCallbackStub::OnSecureUserInfoStub(MessageParcel &data, MessageParcel &reply)
{
    SecUserInfo info = {};
    uint32_t enrolledInfoLen;

    if (!data.ReadUint64(info.secureUid)) {
        IAM_LOGE("failed to read secureUid");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(enrolledInfoLen)) {
        IAM_LOGE("failed to read enrolledInfoLen");
        return READ_PARCEL_ERROR;
    }
    // 调用OnSecureUserInfo(), 参数不一致
    if (getSecInfoCallback_ == nullptr) {
        IAM_LOGE("get secure info callback is nullptr");
        return FAIL;
    }
    getSecInfoCallback_->OnSecUserInfo(info);
    return SUCCESS;
}

void IdmGetSecureUserInfoCallbackStub::OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info)
{
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS