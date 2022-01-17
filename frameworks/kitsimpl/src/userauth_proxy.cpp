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
#include "userauth_common.h"
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

    WRITE_PARCEL_WITH_RET(data, Uint32, static_cast<uint32_t>(authType), E_READ_PARCEL_ERROR);
    WRITE_PARCEL_WITH_RET(data, Uint32, static_cast<uint32_t>(authTurstLevel), E_READ_PARCEL_ERROR);

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

    WRITE_PARCEL_NO_RET(data, Uint32, static_cast<uint32_t>(request.authType));
    WRITE_PARCEL_NO_RET(data, UInt32Vector, (request.keys));
    WRITE_PARCEL_NO_RET(data, RemoteObject, callback->AsObject());

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

    WRITE_PARCEL_NO_RET(data, Uint32, static_cast<uint32_t>(request.authType));
    WRITE_PARCEL_NO_RET(data, Uint32, static_cast<uint32_t>(request.key));
    WRITE_PARCEL_NO_RET(data, UInt8Vector, request.setInfo);
    WRITE_PARCEL_NO_RET(data, RemoteObject, callback->AsObject());

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

    WRITE_PARCEL_WITH_RET(data, Uint64, challenge, E_READ_PARCEL_ERROR);
    WRITE_PARCEL_WITH_RET(data, Uint32, static_cast<uint32_t>(authType), E_READ_PARCEL_ERROR);
    WRITE_PARCEL_WITH_RET(data, Uint32, static_cast<uint32_t>(authTurstLevel), E_READ_PARCEL_ERROR);
    WRITE_PARCEL_WITH_RET(data, RemoteObject, callback->AsObject(), E_READ_PARCEL_ERROR);

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

    WRITE_PARCEL_WITH_RET(data, Int32, userId, E_READ_PARCEL_ERROR);
    WRITE_PARCEL_WITH_RET(data, Uint64, challenge, E_READ_PARCEL_ERROR);
    WRITE_PARCEL_WITH_RET(data, Uint32, static_cast<uint32_t>(authType), E_READ_PARCEL_ERROR);
    WRITE_PARCEL_WITH_RET(data, Uint32, static_cast<uint32_t>(authTurstLevel), E_READ_PARCEL_ERROR);
    WRITE_PARCEL_WITH_RET(data, RemoteObject, callback->AsObject(), E_READ_PARCEL_ERROR);

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

    WRITE_PARCEL_WITH_RET(data, Uint64, contextId, E_READ_PARCEL_ERROR);

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