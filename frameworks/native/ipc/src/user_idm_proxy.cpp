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

#define LOG_LABEL UserIam::Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserIdmProxy::UserIdmProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<UserIdmInterface>(object)
{
}

int32_t UserIdmProxy::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return WRITE_PARCEL_ERROR;
    }
    
    bool ret = SendRequest(UserIdmInterface::USER_IDM_OPEN_SESSION, data, reply);
    if (!ret) {
        return GENERAL_ERROR;
    }
    if (!reply.ReadUInt8Vector(&challenge)) {
        IAM_LOGE("failed to read challenge");
        return READ_PARCEL_ERROR;
    }
    return SUCCESS;
}

void UserIdmProxy::CloseSession(int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return;
    }

    SendRequest(UserIdmInterface::USER_IDM_CLOSE_SESSION, data, reply);
}

int32_t UserIdmProxy::GetCredentialInfo(int32_t userId, AuthType authType,
    const sptr<IdmGetCredInfoCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(authType)) {
        IAM_LOGE("failed to write authType");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserIdmInterface::USER_IDM_GET_CRED_INFO, data, reply);
    if (!ret) {
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

int32_t UserIdmProxy::GetSecInfo(int32_t userId, const sptr<IdmGetSecureUserInfoCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserIdmInterface::USER_IDM_GET_SEC_INFO, data, reply);
    if (!ret) {
        callback->OnSecureUserInfo(nullptr);
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

void UserIdmProxy::AddCredential(int32_t userId, const CredentialPara &credPara,
    const sptr<IdmCallbackInterface> &callback, bool isUpdate)
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
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteInt32(credPara.authType)) {
        IAM_LOGE("failed to write authType");
        return;
    }
    if (!data.WriteInt32(credPara.pinType)) {
        IAM_LOGE("failed to write pinSubType");
        return;
    }
    if (!data.WriteUInt8Vector(credPara.token)) {
        IAM_LOGE("failed to write token");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }

    SendRequest(UserIdmInterface::USER_IDM_ADD_CREDENTIAL, data, reply);
}

void UserIdmProxy::UpdateCredential(int32_t userId, const CredentialPara &credPara,
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
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteInt32(credPara.authType)) {
        IAM_LOGE("failed to write authType");
        return;
    }
    if (!data.WriteInt32(credPara.pinType)) {
        IAM_LOGE("failed to write pinSubType");
        return;
    }
    if (!data.WriteUInt8Vector(credPara.token)) {
        IAM_LOGE("failed to write token");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }

    bool ret = SendRequest(UserIdmInterface::USER_IDM_UPDATE_CREDENTIAL, data, reply);
    if (!ret) {
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
    }
}

int32_t UserIdmProxy::Cancel(int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserIdmInterface::USER_IDM_CANCEL, data, reply);
    if (!ret) {
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

int32_t UserIdmProxy::EnforceDelUser(int32_t userId, const sptr<IdmCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIdmProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserIdmInterface::USER_IDM_ENFORCE_DEL_USER, data, reply);
    if (!ret) {
        Attributes attr;
        callback->OnResult(GENERAL_ERROR, attr);
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

void UserIdmProxy::DelUser(int32_t userId, const std::vector<uint8_t> authToken,
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
    if (!data.WriteInt32(userId)) {
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

    SendRequest(UserIdmInterface::USER_IDM_DEL_USER, data, reply);
}

void UserIdmProxy::DelCredential(int32_t userId, uint64_t credentialId,
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
    if (!data.WriteInt32(userId)) {
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

    SendRequest(UserIdmInterface::USER_IDM_DEL_CRED, data, reply);
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