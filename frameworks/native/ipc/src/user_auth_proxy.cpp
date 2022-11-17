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

#include "user_auth_proxy.h"

#include <algorithm>
#include <cinttypes>

#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const uint64_t BAD_CONTEXT_ID = 0;
} // namespace

UserAuthProxy::UserAuthProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<UserAuthInterface>(object)
{
}

int32_t UserAuthProxy::GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(authType)) {
        IAM_LOGE("failed to write authType");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint32(authTrustLevel)) {
        IAM_LOGE("failed to write authTrustLevel");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(apiVersion)) {
        IAM_LOGE("failed to write apiVersion");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_GET_AVAILABLE_STATUS, data, reply);
    if (!ret) {
        return GENERAL_ERROR;
    }
    int32_t result = SUCCESS;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    return result;
}

void UserAuthProxy::GetProperty(int32_t userId, AuthType authType,
    const std::vector<Attributes::AttributeKey> &keys, sptr<GetExecutorPropertyCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;

    std::vector<uint32_t> attrKeys;
    attrKeys.resize(keys.size());
    std::transform(keys.begin(), keys.end(), attrKeys.begin(), [](Attributes::AttributeKey key) {
        return static_cast<uint32_t>(key);
    });

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteInt32(authType)) {
        IAM_LOGE("failed to write authType");
        return;
    }
    if (!data.WriteUInt32Vector(attrKeys)) {
        IAM_LOGE("failed to write keys");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_GET_PROPERTY, data, reply);
    if (!ret) {
        Attributes attr;
        callback->OnGetExecutorPropertyResult(GENERAL_ERROR, attr);
    }
}

void UserAuthProxy::SetProperty(int32_t userId, AuthType authType, const Attributes &attributes,
    sptr<SetExecutorPropertyCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteInt32(authType)) {
        IAM_LOGE("failed to write authType");
        return;
    }
    auto buffer = attributes.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("failed to write attributes");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_SET_PROPERTY, data, reply);
    if (!ret) {
        callback->OnSetExecutorPropertyResult(GENERAL_ERROR);
    }
}

bool UserAuthProxy::WriteAuthParam(MessageParcel &data, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    if (!data.WriteUInt8Vector(challenge)) {
        IAM_LOGE("failed to write challenge");
        return false;
    }
    if (!data.WriteInt32(authType)) {
        IAM_LOGE("failed to write authType");
        return false;
    }
    if (!data.WriteUint32(authTrustLevel)) {
        IAM_LOGE("failed to write authTrustLevel");
        return false;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return false;
    }
    return true;
}

uint64_t UserAuthProxy::Auth(int32_t apiVersion, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return BAD_CONTEXT_ID;
    }
    if (!WriteAuthParam(data, challenge, authType, authTrustLevel, callback)) {
        IAM_LOGE("failed to write auth param");
        return BAD_CONTEXT_ID;
    }
    if (!data.WriteInt32(apiVersion)) {
        IAM_LOGE("failed to write apiVersion");
        return BAD_CONTEXT_ID;
    }
    bool ret = SendRequest(UserAuthInterface::USER_AUTH_AUTH, data, reply);
    if (!ret) {
        return BAD_CONTEXT_ID;
    }
    uint64_t result = BAD_CONTEXT_ID;
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

uint64_t UserAuthProxy::AuthUser(int32_t userId, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return BAD_CONTEXT_ID;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return BAD_CONTEXT_ID;
    }
    if (!WriteAuthParam(data, challenge, authType, authTrustLevel, callback)) {
        IAM_LOGE("failed to write auth param");
        return BAD_CONTEXT_ID;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_AUTH_USER, data, reply);
    if (!ret) {
        return BAD_CONTEXT_ID;
    }
    uint64_t result = BAD_CONTEXT_ID;
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

uint64_t UserAuthProxy::Identify(const std::vector<uint8_t> &challenge, AuthType authType,
    sptr<UserAuthCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return BAD_CONTEXT_ID;
    }
    if (!data.WriteUInt8Vector(challenge)) {
        IAM_LOGE("failed to write challenge");
        return BAD_CONTEXT_ID;
    }
    if (!data.WriteInt32(authType)) {
        IAM_LOGE("failed to write authType");
        return BAD_CONTEXT_ID;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return BAD_CONTEXT_ID;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_IDENTIFY, data, reply);
    if (!ret) {
        return BAD_CONTEXT_ID;
    }
    uint64_t result = BAD_CONTEXT_ID;
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

int32_t UserAuthProxy::CancelAuthOrIdentify(uint64_t contextId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return GENERAL_ERROR;
    }
    if (!data.WriteUint64(contextId)) {
        IAM_LOGE("failed to write contextId");
        return GENERAL_ERROR;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_CANCEL_AUTH, data, reply);
    if (!ret) {
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

int32_t UserAuthProxy::GetVersion(int32_t &version)
{
    version = 0;
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return GENERAL_ERROR;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_GET_VERSION, data, reply);
    if (!ret) {
        return GENERAL_ERROR;
    }
    if (!reply.ReadInt32(version)) {
        IAM_LOGE("failed to read version");
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

bool UserAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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