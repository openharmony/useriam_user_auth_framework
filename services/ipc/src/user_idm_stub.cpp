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
#include "result_code.h"
#include "user_idm_callback_proxy.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t UserIdmStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGI("cmd = %{public}u, flags= %{public}d", code, option.GetFlags());
    if (data.ReadInterfaceToken() != UserIdmInterface::GetDescriptor()) {
        IAM_LOGE("failed to match descriptor");
        return FAIL;
    }

    switch (code) {
        case USER_IDM_OPEN_SESSION:
            return OpenSessionStub(data, reply);
        case USER_IDM_OPEN_SESSION_BY_ID:
            return OpenSessionByIdStub(data, reply);
        case USER_IDM_CLOSE_SESSION:
            return CloseSessionStub(data, reply);
        case USER_IDM_CLOSE_SESSION_BY_ID:
            return CloseSessionByIdStub(data, reply);
        case USER_IDM_GET_AUTH_INFO:
            return GetCredentialInfoStub(data, reply);
        case USER_IDM_GET_AUTH_INFO_BY_ID:
            return GetCredentialInfoByIdStub(data, reply);
        case USER_IDM_GET_SEC_INFO:
            return GetSecInfoStub(data, reply);
        case USER_IDM_ADD_CREDENTIAL:
            return AddCredentialStub(data, reply);
        case USER_IDM_ADD_CREDENTIAL_BY_ID:
            return AddCredentialByIdStub(data, reply);
        case USER_IDM_UPDATE_CREDENTIAL:
            return UpdateCredentialStub(data, reply);
        case USER_IDM_UPDATE_CREDENTIAL_BY_ID:
            return UpdateCredentialByIdStub(data, reply);
        case USER_IDM_CANCEL:
            return CancelStub(data, reply);
        case USER_IDM_CANCEL_BY_ID:
            return CancelByIdStub(data, reply);
        case USER_IDM_ENFORCE_DEL_USER:
            return EnforceDelUserStub(data, reply);
        case USER_IDM_DEL_USER:
            return DelUserStub(data, reply);
        case USER_IDM_DEL_USER_BY_ID:
            return DelUserByIdStub(data, reply);
        case USER_IDM_DEL_CRED:
            return DelCredentialStub(data, reply);
        case USER_IDM_DEL_CREDENTIAL:
            return DelCredentialByIdStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserIdmStub::OpenSessionStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    static_cast<void>(data);

    std::vector<uint8_t> challenge;

    int32_t ret = OpenSession(std::nullopt, challenge);
    if (ret != SUCCESS) {
        IAM_LOGE("OpenSession fail");
        return ret;
    }

    if (challenge.size() != sizeof(uint64_t)) {
        IAM_LOGE("failed to check challenge size");
        return GENERAL_ERROR;
    }
    if (!reply.WriteUInt8Vector(challenge)) {
        IAM_LOGE("failed to write challenge");
        return WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserIdmStub::OpenSessionByIdStub(MessageParcel &data, MessageParcel &reply)
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

    if (challenge.size() != sizeof(uint64_t)) {
        IAM_LOGE("failed to check challenge size");
        return GENERAL_ERROR;
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

    CloseSession(std::nullopt);
    return SUCCESS;
}

int32_t UserIdmStub::CloseSessionByIdStub(MessageParcel &data, MessageParcel &reply)
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

    uint32_t authType;
    if (!data.ReadUint32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    sptr<IdmGetCredInfoCallbackInterface> callback = iface_cast<IdmGetCredentialInfoProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return READ_PARCEL_ERROR;
    }

    int32_t ret = GetCredentialInfo(std::nullopt, static_cast<AuthType>(authType), callback);
    static_cast<void>(reply.WriteInt32(ret));
    return ret;
}

int32_t UserIdmStub::GetCredentialInfoByIdStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    uint32_t authType;
    if (!data.ReadUint32(authType)) {
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

    uint32_t authType;
    if (!data.ReadUint32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    uint64_t authSubType;
    if (!data.ReadUint64(authSubType)) {
        IAM_LOGE("failed to read authSubType");
        return READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> token = {};
    if (!data.ReadUInt8Vector(&(token))) {
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
    AddCredential(std::nullopt, static_cast<AuthType>(authType), static_cast<PinSubType>(authSubType),
        token, callback, false);
    return SUCCESS;
}

int32_t UserIdmStub::AddCredentialByIdStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    uint32_t authType;
    if (!data.ReadUint32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    uint64_t authSubType;
    if (!data.ReadUint64(authSubType)) {
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
    AddCredential(userId, static_cast<AuthType>(authType), static_cast<PinSubType>(authSubType),
        token, callback, false);
    return SUCCESS;
}

int32_t UserIdmStub::UpdateCredentialStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    uint32_t authType;
    if (!data.ReadUint32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    uint64_t authSubType;
    if (!data.ReadUint64(authSubType)) {
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

    UpdateCredential(std::nullopt, static_cast<AuthType>(authType), static_cast<PinSubType>(authSubType), token,
        callback);
    return SUCCESS;
}

int32_t UserIdmStub::UpdateCredentialByIdStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    uint32_t authType;
    if (!data.ReadUint32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    uint64_t authSubType;
    if (!data.ReadUint64(authSubType)) {
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
        return FAIL;
    }

    UpdateCredential(userId, static_cast<AuthType>(authType), static_cast<PinSubType>(authSubType), token, callback);
    return SUCCESS;
}

int32_t UserIdmStub::CancelStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    std::vector<uint8_t> challenge;
    if (!data.ReadUInt8Vector(&challenge)) {
        IAM_LOGE("failed to read challenge");
        return READ_PARCEL_ERROR;
    }

    int32_t ret = Cancel(std::nullopt, challenge);
    static_cast<void>(reply.WriteInt32(ret));
    return ret;
}

int32_t UserIdmStub::CancelByIdStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }

    int32_t ret = Cancel(userId, std::nullopt);
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

int32_t UserIdmStub::DelUserStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    std::vector<uint8_t> authToken;
    if (!data.ReadUInt8Vector(&authToken)) {
        IAM_LOGE("failed to read authToken");
        return READ_PARCEL_ERROR;
    }

    sptr<IdmCallbackInterface> callback = iface_cast<IdmCallbackProxy>(data.ReadRemoteObject());
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return READ_PARCEL_ERROR;
    }

    DelUser(std::nullopt, authToken, callback);
    return SUCCESS;
}

int32_t UserIdmStub::DelUserByIdStub(MessageParcel &data, [[maybe_unused]] MessageParcel &reply)
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
        return READ_PARCEL_ERROR;
    }

    DelCredential(std::nullopt, credentialId, authToken, callback);
    return SUCCESS;
}

int32_t UserIdmStub::DelCredentialByIdStub(MessageParcel &data, MessageParcel &reply)
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
        return FAIL;
    }

    DelCredential(userId, credentialId, authToken, callback);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS