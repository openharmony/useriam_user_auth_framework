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
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
UserAuthProxy::UserAuthProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IUserAuth>(object)
{
}

int32_t UserAuthProxy::GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy GetAvailableStatus start");
    int32_t result = SUCCESS;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return GENERAL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write authType");
        return GENERAL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTrustLevel))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write authTrustLevel");
        return GENERAL_ERROR;
    }
    bool ret = SendRequest(static_cast<int32_t>(IUserAuth::USER_AUTH_GET_AVAILABLE_STATUS), data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed");
        return GENERAL_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to read result");
        return GENERAL_ERROR;
    }

    return result;
}

void UserAuthProxy::GetProperty(const GetPropertyRequest request, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy GetProperty start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write request.authType");
        return;
    }
    if (!data.WriteUInt32Vector(request.keys)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write request.keys");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write callback");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(IUserAuth::USER_AUTH_GET_PROPERTY), data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed");
        ExecutorProperty result = {};
        result.result = IPC_ERROR;
        callback->onExecutorPropertyInfo(result);
    }
}

void UserAuthProxy::GetProperty(const int32_t userId, const GetPropertyRequest request, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy GetProperty start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return;
    }
    if (!data.WriteInt32(userId)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write userId");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write request.authType");
        return;
    }
    if (!data.WriteUInt32Vector(request.keys)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write request.keys");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write callback");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(IUserAuth::USER_AUTH_GET_PROPERTY_BY_ID), data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed");
        ExecutorProperty result = {};
        result.result = IPC_ERROR;
        callback->onExecutorPropertyInfo(result);
    }
}

void UserAuthProxy::SetProperty(const SetPropertyRequest request, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy SetProperty start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write request.authType");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.key))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write request.key");
        return;
    }
    if (!data.WriteUInt8Vector(request.setInfo)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write request.setInfo");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write callback");
        return;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_SET_PROPERTY, data, reply, option);
    if (!ret) {
        int32_t result = IPC_ERROR;
        callback->onSetExecutorProperty(result);
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed");
        return;
    }
}

uint64_t UserAuthProxy::Auth(const uint64_t challenge, const AuthType authType, const AuthTrustLevel authTrustLevel,
    sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy Auth start");
    const uint64_t invalidContextID = 0;
    uint64_t result = invalidContextID;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return invalidContextID;
    }
    USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthProxy::Auth challenge = %{public}04" PRIx64 "", challenge);
    if (!data.WriteUint64(challenge)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write challenge");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write authType");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTrustLevel))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write authTrustLevel");
        return invalidContextID;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write callback");
        return invalidContextID;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_AUTH, data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed");
        return invalidContextID;
    }
    if (!reply.ReadUint64(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to read result");
    }

    return result;
}

uint64_t UserAuthProxy::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy AuthUser start");
    const uint64_t invalidContextID = 0;
    uint64_t result = invalidContextID;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return invalidContextID;
    }
    if (!data.WriteInt32(userId)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write userId");
        return invalidContextID;
    }
    if (!data.WriteUint64(challenge)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write challenge");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write authType");
        return invalidContextID;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTrustLevel))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write authTrustLevel");
        return invalidContextID;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write callback");
        return invalidContextID;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_AUTH_USER, data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed");
        return invalidContextID;
    }
    if (!reply.ReadUint64(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to read result");
    }

    return result;
}

int32_t UserAuthProxy::CancelAuth(const uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy CancelAuth start");
    int32_t result = GENERAL_ERROR;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return E_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(contextId)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to write contextId");
        return E_WRITE_PARCEL_ERROR;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_CANCEL_AUTH, data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed");
        return IPC_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to read result");
    }

    return result;
}

int32_t UserAuthProxy::GetVersion()
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy GetVersion start");
    int32_t result = GENERAL_ERROR;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return result;
    }

    bool ret = SendRequest(IUserAuth::USER_AUTH_GET_VERSION, data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed");
        return IPC_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to read result");
    }

    return result;
}

bool UserAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption option)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy SendRequest start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return false;
    }

    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::UserIAM::UserAuth::SUCCESS) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthProxy SendRequest failed");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
