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

#include "user_idm_proxy.h"

#include <cinttypes>

#include "iam_logger.h"
#include "securec.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserIdmProxy::UserIdmProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<UserIdmInterface>(object)
{
}

int32_t UserIdmProxy::OpenSession(std::optional<int32_t> userId, std::vector<uint8_t> &challenge)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return FAIL;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return FAIL;
    }
    
    bool ret = SendRequest(userId.has_value() ? UserIdmInterface::USER_IDM_OPEN_SESSION_BY_ID :
        UserIdmInterface::USER_IDM_OPEN_SESSION, data, reply);
    if (!ret) {
        return FAIL;
    }
    uint64_t tempChallenge;
    if (!reply.ReadUint64(tempChallenge)) {
        IAM_LOGE("failed to read challenge");
        return FAIL;
    }
    challenge.resize(sizeof(uint64_t));
    if (memcpy_s(&challenge[0], challenge.size(), &tempChallenge, sizeof(uint64_t)) != EOK) {
        IAM_LOGE("failed to copy challenge");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

void UserIdmProxy::CloseSession(std::optional<int32_t> userId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return;
    }

    SendRequest(userId.has_value() ? UserIdmInterface::USER_IDM_CLOSE_SESSION_BY_ID :
        UserIdmInterface::USER_IDM_CLOSE_SESSION, data, reply);
}

int32_t UserIdmProxy::GetCredentialInfo(std::optional<int32_t> userId, AuthType authType,
    const sptr<IdmGetCredInfoCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return FAIL;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return FAIL;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return FAIL;
    }
    if (!data.WriteUint32(authType)) {
        IAM_LOGE("failed to write authType");
        return FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return FAIL;
    }

    bool ret = SendRequest(userId.has_value() ? UserIdmInterface::USER_IDM_GET_AUTH_INFO_BY_ID :
        UserIdmInterface::USER_IDM_GET_AUTH_INFO, data, reply);
    if (!ret) {
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

int32_t UserIdmProxy::GetSecInfo(std::optional<int32_t> userId,
    const sptr<IdmGetSecureUserInfoCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return FAIL;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return FAIL;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return FAIL;
    }

    bool ret = SendRequest(UserIdmInterface::USER_IDM_GET_SEC_INFO, data, reply);
    if (!ret) {
        callback->OnSecureUserInfo(nullptr);
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

void UserIdmProxy::AddCredential(std::optional<int32_t> userId, AuthType authType, PinSubType pinSubType,
    const std::vector<uint8_t> &token, const sptr<IdmCallbackInterface> &callback, bool isUpdate)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteUint32(authType)) {
        IAM_LOGE("failed to write authType");
        return;
    }
    if (!data.WriteUint64(pinSubType)) {
        IAM_LOGE("failed to write pinSubType");
        return;
    }
    if (!data.WriteUInt8Vector(token)) {
        IAM_LOGE("failed to write token");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }

    SendRequest(userId.has_value() ? UserIdmInterface::USER_IDM_ADD_CREDENTIAL_BY_ID :
        UserIdmInterface::USER_IDM_ADD_CREDENTIAL, data, reply);
}

void UserIdmProxy::UpdateCredential(std::optional<int32_t> userId, AuthType authType, PinSubType pinSubType,
    const std::vector<uint8_t> &token, const sptr<IdmCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteUint32(authType)) {
        IAM_LOGE("failed to write authType");
        return;
    }
    if (!data.WriteUint64(pinSubType)) {
        IAM_LOGE("failed to write pinSubType");
        return;
    }
    if (!data.WriteUInt8Vector(token)) {
        IAM_LOGE("failed to write token");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }

    bool ret = SendRequest(userId.has_value() ? UserIdmInterface::USER_IDM_UPDATE_CREDENTIAL_BY_ID :
        UserIdmInterface::USER_IDM_UPDATE_CREDENTIAL, data, reply);
    if (!ret) {
        Attributes extraInfo;
        callback->OnResult(FAIL, extraInfo);
    }
}

int32_t UserIdmProxy::Cancel(std::optional<int32_t> userId, const std::optional<std::vector<uint8_t>> &challenge)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return FAIL;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return FAIL;
    }
    if (challenge.has_value() && !data.WriteUInt8Vector(challenge.value())) {
        IAM_LOGE("failed to write challenge");
        return FAIL;
    }

    bool ret = SendRequest(userId.has_value() ? UserIdmInterface::USER_IDM_CANCEL_BY_ID :
        UserIdmInterface::USER_IDM_CANCEL, data, reply);
    if (!ret) {
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

int32_t UserIdmProxy::EnforceDelUser(int32_t userId, const sptr<IdmCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return FAIL;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return FAIL;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return FAIL;
    }

    bool ret = SendRequest(UserIdmInterface::USER_IDM_ENFORCE_DEL_USER, data, reply);
    if (!ret) {
        Attributes attr;
        callback->OnResult(FAIL, attr);
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

void UserIdmProxy::DelUser(std::optional<int32_t> userId, const std::vector<uint8_t> authToken,
    const sptr<IdmCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteUInt8Vector(authToken)) {
        IAM_LOGE("failed to write authToken");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }

    SendRequest(userId.has_value() ? UserIdmInterface::USER_IDM_DEL_USER_BY_ID :
        UserIdmInterface::USER_IDM_DEL_USER, data, reply);
}

void UserIdmProxy::DelCredential(std::optional<int32_t> userId, uint64_t credentialId,
    const std::vector<uint8_t> &authToken, const sptr<IdmCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteUint64(credentialId)) {
        IAM_LOGE("failed to write credentialId");
        return;
    }
    if (!data.WriteUInt8Vector(authToken)) {
        IAM_LOGE("failed to write authToken");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }

    SendRequest(userId.has_value() ? UserIdmInterface::USER_IDM_DEL_CREDENTIAL :
        UserIdmInterface::USER_IDM_DEL_CRED, data, reply);
}

bool UserIdmProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("failed to send request, result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS