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

int32_t UserAuthProxy::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel)
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

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_GET_AVAILABLE_STATUS, data, reply);
    if (!ret) {
        return FAIL;
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
        callback->OnGetExecutorPropertyResult(FAIL, attr);
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
        callback->OnSetExecutorPropertyResult(FAIL);
    }
}

uint64_t UserAuthProxy::AuthUser(std::optional<int32_t> userId, const std::vector<uint8_t> &challenge,
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
    if (userId.has_value() && !data.WriteInt32(userId.value())) {
        IAM_LOGE("failed to write userId");
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
    if (!data.WriteUint32(authTrustLevel)) {
        IAM_LOGE("failed to write authTrustLevel");
        return BAD_CONTEXT_ID;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return BAD_CONTEXT_ID;
    }

    bool ret = SendRequest(userId.has_value() ? UserAuthInterface::USER_AUTH_AUTH_USER :
        UserAuthInterface::USER_AUTH_AUTH, data, reply);
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
        return FAIL;
    }
    if (!data.WriteUint64(contextId)) {
        IAM_LOGE("failed to write contextId");
        return FAIL;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_CANCEL_AUTH, data, reply);
    if (!ret) {
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

int32_t UserAuthProxy::GetVersion()
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return FAIL;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_GET_VERSION, data, reply);
    if (!ret) {
        return FAIL;
    }
    int32_t result = FAIL;
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