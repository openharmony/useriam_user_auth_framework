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

#include "userauth_stub.h"
#include <message_parcel.h>
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
int32_t UserAuthStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub::OnRemoteRequest cmd = %{public}u, flags= %{public}d", code,
        option.GetFlags());
    std::u16string descripter = UserAuthStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        USERAUTH_HILOGD(MODULE_SERVICE, "DisplayMgrStub::OnRemoteRequest failed, descriptor is not matched!");
        return E_GET_POWER_SERVICE_FAILED;
    }

    switch (code) {
        case static_cast<uint32_t>(IUserAuth::USER_AUTH_GET_AVAILABLE_STATUS):
            return GetAvailableStatusStub(data, reply);
        case static_cast<uint32_t>(IUserAuth::USER_AUTH_GET_PROPERTY):
            return GetPropertyStub(data, reply);
        case static_cast<uint32_t>(IUserAuth::USER_AUTH_GET_PROPERTY_BY_ID):
            return GetPropertyByIdStub(data, reply);
        case static_cast<uint32_t>(IUserAuth::USER_AUTH_SET_PROPERTY):
            return SetPropertyStub(data, reply);
        case static_cast<uint32_t>(IUserAuth::USER_AUTH_AUTH):
            return AuthStub(data, reply);
        case static_cast<uint32_t>(IUserAuth::USER_AUTH_AUTH_USER):
            return AuthUserStub(data, reply);
        case static_cast<uint32_t>(IUserAuth::USER_AUTH_CANCEL_AUTH):
            return CancelAuthStub(data, reply);
        case static_cast<uint32_t>(IUserAuth::USER_AUTH_GET_VERSION):
            return GetVersionStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserAuthStub::GetAvailableStatusStub(MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub GetAvailableStatusStub start");
    uint32_t authType;
    uint32_t authTrustLevel;
    int32_t ret = GENERAL_ERROR;

    if (!data.ReadUint32(authType)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authType");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authTrustLevel)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authTrustLevel");
        return E_READ_PARCEL_ERROR;
    }

    ret = GetAvailableStatus(static_cast<AuthType>(authType), static_cast<AuthTrustLevel>(authTrustLevel));
    if (!reply.WriteInt32(ret)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to write GetAvailableStatus result");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserAuthStub::GetPropertyStub(MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub GetPropertyStub start");
    GetPropertyRequest getPropertyRequest;
    uint32_t authType;
    std::vector<uint32_t> keys;

    if (!data.ReadUint32(authType)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authType");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt32Vector(&keys)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read keys");
        return E_READ_PARCEL_ERROR;
    }

    getPropertyRequest.authType = static_cast<AuthType>(authType);
    getPropertyRequest.keys = keys;

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        return E_READ_PARCEL_ERROR;
    }

    sptr<IUserAuthCallback> callback = iface_cast<IUserAuthCallback>(obj);
    if (callback == nullptr) {
        return FAIL;
    }

    GetProperty(getPropertyRequest, callback);
    return SUCCESS;
}

int32_t UserAuthStub::GetPropertyByIdStub(MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub GetPropertyStub start");
    GetPropertyRequest getPropertyRequest;
    int32_t userId;
    uint32_t authType;
    std::vector<uint32_t> keys;

    if (!data.ReadInt32(userId)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read userId");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authType)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authType");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt32Vector(&keys)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read keys");
        return E_READ_PARCEL_ERROR;
    }

    getPropertyRequest.authType = static_cast<AuthType>(authType);
    getPropertyRequest.keys = keys;

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        return E_READ_PARCEL_ERROR;
    }

    sptr<IUserAuthCallback> callback = iface_cast<IUserAuthCallback>(obj);
    if (callback == nullptr) {
        return FAIL;
    }

    GetProperty(userId, getPropertyRequest, callback);
    return SUCCESS;
}

int32_t UserAuthStub::SetPropertyStub(MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub SetPropertyStub start");
    SetPropertyRequest setPropertyRequest;
    uint32_t authType;
    uint32_t key;
    std::vector<uint8_t> setInfo;

    if (!data.ReadUint32(authType)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authType");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(key)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read key");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&setInfo)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read setInfo");
        return E_READ_PARCEL_ERROR;
    }

    setPropertyRequest.authType = static_cast<AuthType>(authType);
    setPropertyRequest.key = static_cast<SetPropertyType>(key);
    setPropertyRequest.setInfo.assign(setInfo.begin(), setInfo.end());

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        return E_READ_PARCEL_ERROR;
    }

    sptr<IUserAuthCallback> callback = iface_cast<IUserAuthCallback>(obj);
    if (callback == nullptr) {
        return FAIL;
    }

    SetProperty(setPropertyRequest, callback);

    return SUCCESS;
}

int32_t UserAuthStub::AuthStub(MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub AuthStub start");
    uint64_t challenge;
    uint32_t authType;
    uint32_t authTrustLevel;
    uint64_t ret = SUCCESS;

    if (!data.ReadUint64(challenge)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read challenge");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authType)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authType");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authTrustLevel)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authTrustLevel");
        return E_READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        return E_READ_PARCEL_ERROR;
    }

    sptr<IUserAuthCallback> callback = iface_cast<IUserAuthCallback>(obj);
    if (callback == nullptr) {
        return FAIL;
    }

    ret = Auth(challenge, static_cast<AuthType>(authType), static_cast<AuthTrustLevel>(authTrustLevel), callback);
    if (!reply.WriteUint64(ret)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to write Auth result");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserAuthStub::AuthUserStub(MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub AuthUserStub start");
    int32_t userId;
    uint64_t challenge;
    uint32_t authType;
    uint32_t authTrustLevel;

    if (!data.ReadInt32(userId)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read userId");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint64(challenge)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read challenge");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authType)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authType");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authTrustLevel)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read authTrustLevel");
        return E_READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        return E_READ_PARCEL_ERROR;
    }

    sptr<IUserAuthCallback> callback = iface_cast<IUserAuthCallback>(obj);
    if (callback == nullptr) {
        return FAIL;
    }

    uint64_t ret = AuthUser(userId, challenge, static_cast<AuthType>(authType),
        static_cast<AuthTrustLevel>(authTrustLevel), callback);
    if (!reply.WriteUint64(ret)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to write AuthUser result");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserAuthStub::GetVersionStub(MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub GetVersionStub start");

    int32_t ret = GetVersion();
    if (!reply.WriteInt32(ret)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to write GetVersion result");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserAuthStub::CancelAuthStub(MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthStub CancelAuthStub start");
    uint64_t contextId;
    int32_t ret = GENERAL_ERROR;

    if (!data.ReadUint64(contextId)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to read contextId");
        return E_READ_PARCEL_ERROR;
    }

    ret = CancelAuth(contextId);
    if (!reply.WriteInt32(ret)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to write CancelAuth result");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
