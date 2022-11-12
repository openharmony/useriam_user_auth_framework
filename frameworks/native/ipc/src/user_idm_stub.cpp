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

#include "user_idm_stub.h"

#include <cinttypes>

#include "iam_logger.h"
#include "iam_scope_guard.h"
#include "iam_common_defines.h"
#include "user_idm_callback_proxy.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t UserIdmStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGI("cmd = %{public}u, flags= %{public}d", code, option.GetFlags());
    if (data.ReadInterfaceToken() != UserIdmInterface::GetDescriptor()) {
        IAM_LOGE("failed to match descriptor");
        return GENERAL_ERROR;
    }

    switch (code) {
        case USER_IDM_OPEN_SESSION:
            return OpenSessionStub(data, reply);
        case USER_IDM_CLOSE_SESSION:
            return CloseSessionStub(data, reply);
        case USER_IDM_GET_CRED_INFO:
            return GetCredentialInfoStub(data, reply);
        case USER_IDM_GET_SEC_INFO:
            return GetSecInfoStub(data, reply);
        case USER_IDM_ADD_CREDENTIAL:
            return AddCredentialStub(data, reply);
        case USER_IDM_UPDATE_CREDENTIAL:
            return UpdateCredentialStub(data, reply);
        case USER_IDM_CANCEL:
            return CancelStub(data, reply);
        case USER_IDM_ENFORCE_DEL_USER:
            return EnforceDelUserStub(data, reply);
        case USER_IDM_DEL_USER:
            return DelUserStub(data, reply);
        case USER_IDM_DEL_CRED:
            return DelCredentialStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserIdmStub::OpenSessionStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    std::vector<uint8_t> challenge;
    int32_t ret = OpenSession(userId, challenge);
    if (ret != SUCCESS) {
        return ret;
    }

    if (!reply.WriteUInt8Vector(challenge)) {
        IAM_LOGE("failed to write challenge");
        return WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserIdmStub::CloseSessionStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;

    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    CloseSession(userId);
    return SUCCESS;
}

int32_t UserIdmStub::GetCredentialInfoStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    int32_t authType;
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    sptr<IdmGetCredInfoCallbackInterface> callback = iface_cast<IdmGetCredentialInfoProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return ERR_INVALID_VALUE;
    }

    int32_t ret = GetCredentialInfo(userId, static_cast<AuthType>(authType), callback);
    static_cast<void>(reply.WriteInt32(ret));
    return ret;
}

int32_t UserIdmStub::GetSecInfoStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }
    sptr<IdmGetSecureUserInfoCallbackInterface> callback =
        iface_cast<IdmGetSecureUserInfoProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return ERR_INVALID_VALUE;
    }

    int32_t ret = GetSecInfo(userId, callback);
    static_cast<void>(reply.WriteInt32(ret));
    return ret;
}

int32_t UserIdmStub::AddCredentialStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    int32_t authType;
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    int32_t authSubType;
    if (!data.ReadInt32(authSubType)) {
        IAM_LOGE("failed to read authSubType");
        return READ_PARCEL_ERROR;
    }

    std::vector<uint8_t> token;
    if (!data.ReadUInt8Vector(&token)) {
        IAM_LOGE("failed to read token");
        return READ_PARCEL_ERROR;
    }

    sptr<IdmCallbackInterface> callback = iface_cast<IdmCallbackProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return READ_PARCEL_ERROR;
    }
    if (authType == PIN && !token.empty()) {
        IAM_LOGI("auth type is pin, clear token");
        token.clear();
    }
    CredentialPara credPara = {};
    credPara.authType = static_cast<AuthType>(authType);
    credPara.pinType = static_cast<PinSubType>(authSubType);
    credPara.token = token;
    AddCredential(userId, credPara, callback, false);
    return SUCCESS;
}

int32_t UserIdmStub::UpdateCredentialStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    int32_t authType;
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    int32_t authSubType;
    if (!data.ReadInt32(authSubType)) {
        IAM_LOGE("failed to read authSubType");
        return READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> token = {};
    if (!data.ReadUInt8Vector(&token)) {
        IAM_LOGE("failed to read token");
        return READ_PARCEL_ERROR;
    }

    sptr<IdmCallbackInterface> callback = iface_cast<IdmCallbackProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    CredentialPara credPara = {};
    credPara.authType = static_cast<AuthType>(authType);
    credPara.pinType = static_cast<PinSubType>(authSubType);
    credPara.token = token;
    UpdateCredential(userId, credPara, callback);
    return SUCCESS;
}

int32_t UserIdmStub::CancelStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    int32_t ret = Cancel(userId);
    static_cast<void>(reply.WriteInt32(ret));
    return ret;
}

int32_t UserIdmStub::EnforceDelUserStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    sptr<IdmCallbackInterface> callback = iface_cast<IdmCallbackProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return READ_PARCEL_ERROR;
    }

    int32_t ret = EnforceDelUser(userId, callback);
    static_cast<void>(reply.WriteInt32(ret));
    return ret;
}

int32_t UserIdmStub::DelUserStub(MessageParcel &data, [[maybe_unused]] MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    std::vector<uint8_t> authToken = {};
    if (!data.ReadUInt8Vector(&authToken)) {
        IAM_LOGE("failed to read authToken");
        return READ_PARCEL_ERROR;
    }

    sptr<IdmCallbackInterface> callback = iface_cast<IdmCallbackProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return READ_PARCEL_ERROR;
    }

    DelUser(userId, authToken, callback);
    return SUCCESS;
}

int32_t UserIdmStub::DelCredentialStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    uint64_t credentialId;
    if (!data.ReadUint64(credentialId)) {
        IAM_LOGE("failed to read credentialId");
        return READ_PARCEL_ERROR;
    }

    std::vector<uint8_t> authToken;
    if (!data.ReadUInt8Vector(&authToken)) {
        IAM_LOGE("failed to read authToken");
        return READ_PARCEL_ERROR;
    }

    sptr<IdmCallbackInterface> callback = iface_cast<IdmCallbackProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    DelCredential(userId, credentialId, authToken, callback);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS