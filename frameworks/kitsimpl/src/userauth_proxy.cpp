/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <message_parcel.h>
#include <string_ex.h>
#include "userauth_hilog_wrapper.h"
#include "userauth_proxy.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
UserAuthProxy::UserAuthProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IUserAuth>(object) {}

int32_t UserAuthProxy::GetAvailableStatus(const AuthType authType, const AuthTurstLevel authTurstLevel)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy GetAvailableStatus is start");
    int32_t result = GENERAL_ERROR;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth write descriptor failed!");
        return result;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(authType)).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTurstLevel))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(authTurstLevel)).");
        return E_READ_PARCEL_ERROR;
    }
    bool ret = SendRequest(static_cast<int32_t>(IUserAuth::USER_AUTH_GET_AVAILABLE_STATUS), data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth SendRequest is failed, error code: %d", ret);
        return IPC_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth Readback fail!");
    }

    return result;
}

void UserAuthProxy::GetProperty(const GetPropertyRequest request, sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy GetProperty is start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth write descriptor failed!");
        return ;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(request.authType)).");
        return;
    }
    if (!data.WriteUInt32Vector(request.keys)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUInt32Vector(request.keys)).");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteRemoteObject(callback->AsObject()).");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(IUserAuth::USER_AUTH_GET_PROPERTY), data, reply, option);
    if (!ret) {
        ExecutorProperty result;
        result.result = IPC_ERROR;
        callback->onExecutorPropertyInfo(result);
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth SendRequest is failed, error code: %d", ret);
        return ;
    }
}
void UserAuthProxy::SetProperty(const SetPropertyRequest request, sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy SetProperty is start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth write descriptor failed!");
        return ;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(request.authType)).");
        return;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(request.key))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(request.key)).");
        return;
    }
    if (!data.WriteUInt8Vector(request.setInfo)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUInt8Vector(request.setInfo).");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteRemoteObject(callback->AsObject()).");
        return;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_SET_PROPERTY, data, reply, option);
    if (!ret) {
        int32_t result = IPC_ERROR;
        callback->onSetExecutorProperty(result);
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth SendRequest is failed, error code: %d", ret);
        return ;
    }
}

uint64_t UserAuthProxy::Auth(const uint64_t challenge, const AuthType authType,
                             const AuthTurstLevel authTurstLevel, sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy Auth is start");
    u_int64_t result = SUCCESS;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth write descriptor failed!");
        return result;
    }
    USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthProxy::Auth challenge = %{public}llu", challenge);
    if (!data.WriteUint64(challenge)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint64(challenge).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(authType)).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTurstLevel))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(authTurstLevel)).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteRemoteObject(callback->AsObject()).");
        return E_READ_PARCEL_ERROR;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_AUTH, data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth SendRequest is failed, error code: %d", ret);
        return result;
    }
    if (!reply.ReadUint64(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth Readback fail!");
        return result;
    }

    return result;
}

uint64_t UserAuthProxy::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
                                 const AuthTurstLevel authTurstLevel, sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy AuthUser is start");
    u_int64_t result = SUCCESS;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return result;
    }
    if (!data.WriteInt32(userId)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteInt32(userId).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.WriteUint64(challenge)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint64(challenge).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authType))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(authType)).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(authTurstLevel))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(static_cast<uint32_t>(authTurstLevel)).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteRemoteObject(callback->AsObject()).");
        return E_READ_PARCEL_ERROR;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_AUTH_USER, data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest is failed, error code: %d", ret);
        return result;
    }
    if (!reply.ReadUint64(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth Readback fail!");
        return result;
    }

    return result;
}

int32_t UserAuthProxy::CancelAuth(const uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy CancelAuth is start");
    int32_t result = GENERAL_ERROR;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return result;
    }
    if (!data.WriteUint64(contextId)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint64(contextId).");
        return E_READ_PARCEL_ERROR;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_CANCEL_AUTH, data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest is failed, error code: %d", ret);
        return IPC_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "Readback fail!");
    }

    return result;
}

int32_t UserAuthProxy::GetVersion()
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy GetVersion is start");
    int32_t result = GENERAL_ERROR;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return result;
    }

    bool ret = SendRequest(IUserAuth::USER_AUTH_GET_VERSION, data, reply, option);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "SendRequest is failed, error code: %d", ret);
        return IPC_ERROR;
    }
    if (!reply.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "Readback fail!");
    }

    return result;
}

bool UserAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption option)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthProxy SendRequest is start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return false;
    }
    
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::UserIAM::UserAuth::SUCCESS) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthProxy SendRequest fail");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
