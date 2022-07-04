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

#include "userauth_proxy.h"

#include <cinttypes>
#include <message_parcel.h>

#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
UserAuthProxy::UserAuthProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IUserAuth>(object)
{
}

int32_t UserAuthProxy::GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel)
{
    IAM_LOGD("UserAuthProxy GetAvailableStatus start");
    int32_t result = SUCCESS;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return GENERAL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        IAM_LOGE("failed to write authType");
        return GENERAL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTrustLevel))) {
        IAM_LOGE("failed to write authTrustLevel");
        return GENERAL_ERROR;
    }
    bool ret = SendRequest(static_cast<int32_t>(IUserAuth::USER_AUTH_GET_AVAILABLE_STATUS), data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        return GENERAL_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return GENERAL_ERROR;
    }

    return result;
}

void UserAuthProxy::GetProperty(const GetPropertyRequest request, sptr<IUserAuthCallback> &callback)
{
    IAM_LOGD("UserAuthProxy GetProperty start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed!");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.authType))) {
        IAM_LOGE("failed to write request.authType");
        return;
    }
    if (!data.WriteUInt32Vector(request.keys)) {
        IAM_LOGE("failed to write request.keys");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(IUserAuth::USER_AUTH_GET_PROPERTY), data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        ExecutorProperty result = {};
        result.result = IPC_ERROR;
        callback->onExecutorPropertyInfo(result);
    }
}

void UserAuthProxy::GetProperty(const int32_t userId, const GetPropertyRequest request,
    sptr<IUserAuthCallback> &callback)
{
    IAM_LOGD("UserAuthProxy GetProperty start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed!");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.authType))) {
        IAM_LOGE("failed to write request.authType");
        return;
    }
    if (!data.WriteUInt32Vector(request.keys)) {
        IAM_LOGE("failed to write request.keys");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(IUserAuth::USER_AUTH_GET_PROPERTY_BY_ID), data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        ExecutorProperty result = {};
        result.result = IPC_ERROR;
        callback->onExecutorPropertyInfo(result);
    }
}

void UserAuthProxy::SetProperty(const SetPropertyRequest request, sptr<IUserAuthCallback> &callback)
{
    IAM_LOGD("UserAuthProxy SetProperty start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.authType))) {
        IAM_LOGE("failed to write request.authType");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.key))) {
        IAM_LOGE("failed to write request.key");
        return;
    }
    if (!data.WriteUInt8Vector(request.setInfo)) {
        IAM_LOGE("failed to write request.setInfo");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_SET_PROPERTY, data, reply, option);
    if (!ret) {
        int32_t result = IPC_ERROR;
        callback->onSetExecutorProperty(result);
        IAM_LOGE("SendRequest failed");
        return;
    }
}

uint64_t UserAuthProxy::Auth(const uint64_t challenge, const AuthType authType, const AuthTrustLevel authTrustLevel,
    sptr<IUserAuthCallback> &callback)
{
    IAM_LOGD("UserAuthProxy Auth start");
    const uint64_t invalidContextID = 0;
    uint64_t result = invalidContextID;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return invalidContextID;
    }
    IAM_LOGE("UserAuthProxy::Auth challenge = %{public}04" PRIx64 "", challenge);
    if (!data.WriteUint64(challenge)) {
        IAM_LOGE("failed to write challenge");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        IAM_LOGE("failed to write authType");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTrustLevel))) {
        IAM_LOGE("failed to write authTrustLevel");
        return invalidContextID;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return invalidContextID;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_AUTH, data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        return invalidContextID;
    }
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
    }

    return result;
}

uint64_t UserAuthProxy::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, sptr<IUserAuthCallback> &callback)
{
    IAM_LOGD("UserAuthProxy AuthUser start");
    const uint64_t invalidContextID = 0;
    uint64_t result = invalidContextID;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return invalidContextID;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("failed to write userId");
        return invalidContextID;
    }
    if (!data.WriteUint64(challenge)) {
        IAM_LOGE("failed to write challenge");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        IAM_LOGE("failed to write authType");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTrustLevel))) {
        IAM_LOGE("failed to write authTrustLevel");
        return invalidContextID;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return invalidContextID;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_AUTH_USER, data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        return invalidContextID;
    }
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
    }

    return result;
}

int32_t UserAuthProxy::CancelAuth(const uint64_t contextId)
{
    IAM_LOGD("UserAuthProxy CancelAuth start");
    int32_t result = GENERAL_ERROR;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return E_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(contextId)) {
        IAM_LOGE("failed to write contextId");
        return E_WRITE_PARCEL_ERROR;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_CANCEL_AUTH, data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        return IPC_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }

    return result;
}

uint64_t UserAuthProxy::Identify(const uint64_t challenge, const AuthType authType,
    sptr<IUserAuthCallback> &callback)
{
    IAM_LOGD("UserAuthProxy Identify start");
    const uint64_t invalidContextID = 0;
    uint64_t result = invalidContextID;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return invalidContextID;
    }
    if (!data.WriteUint64(challenge)) {
        IAM_LOGE("failed to write challenge");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        IAM_LOGE("failed to write authType");
        return invalidContextID;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return invalidContextID;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_IDENTIFY, data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        return invalidContextID;
    }
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
    }

    return result;
}

int32_t UserAuthProxy::CancelIdentify(const uint64_t contextId)
{
    IAM_LOGD("UserAuthProxy CancelIdentify start");
    int32_t result = GENERAL_ERROR;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return E_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(contextId)) {
        IAM_LOGE("failed to write contextId");
        return E_WRITE_PARCEL_ERROR;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_CANCEL_IDENTIFY, data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        return IPC_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }

    return result;
}

int32_t UserAuthProxy::GetVersion()
{
    IAM_LOGD("UserAuthProxy GetVersion start");
    int32_t result = GENERAL_ERROR;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return result;
    }

    bool ret = SendRequest(IUserAuth::USER_AUTH_GET_VERSION, data, reply, option);
    if (!ret) {
        IAM_LOGE("SendRequest failed");
        return IPC_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
    }

    return result;
}

bool UserAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption option)
{
    IAM_LOGD("UserAuthProxy SendRequest start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return false;
    }

    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("UserAuthProxy SendRequest failed");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
