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

#include "useridm_proxy.h"
#include <cinttypes>
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
uint64_t UserIDMProxy::OpenSession()
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return FAIL;
    }

    uint64_t challenge = 0;
    bool ret = SendRequest(USERIDM_OPEN_SESSION, data, reply);
    if (ret) {
        challenge = reply.ReadUint64();
        USERIDM_HILOGI(MODULE_CLIENT, "challenge = 0xXXXX%{public}04" PRIx64, MASK & challenge);
    }
    return challenge;
}

void UserIDMProxy::CloseSession()
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return;
    }

    bool ret = SendRequest(USERIDM_CLOSE_SESSION, data, reply);
    if (ret) {
        USERIDM_HILOGE(MODULE_CLIENT, "ret = %{public}d", ret);
    }
}

int32_t UserIDMProxy::GetAuthInfo(AuthType authType, const sptr<IGetInfoCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return FAIL;
    }

    if (!data.WriteUint32(authType)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint32(authType)");
        return FAIL;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteRemoteObject(callback)");
        return FAIL;
    }

    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_GET_AUTH_INFO, data, reply, true);
    if (ret) {
        result = reply.ReadInt32();
        USERIDM_HILOGI(MODULE_CLIENT, "result = %{public}d", result);
    }
    return result;
}

int32_t UserIDMProxy::GetAuthInfo(int32_t userId, AuthType authType, const sptr<IGetInfoCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return FAIL;
    }

    if (!data.WriteInt32(userId)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteInt32(userId)");
        return FAIL;
    }

    if (!data.WriteUint32(authType)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint32(authType)");
        return FAIL;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteRemoteObject(callback)");
        return FAIL;
    }

    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_GET_AUTH_INFO_BY_ID, data, reply, true);
    if (ret) {
        result = reply.ReadInt32();
        USERIDM_HILOGI(MODULE_CLIENT, "result = %{public}d", result);
    }
    return result;
}

int32_t UserIDMProxy::GetSecInfo(int32_t userId, const sptr<IGetSecInfoCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return FAIL;
    }

    if (!data.WriteInt32(userId)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteInt32(userId)");
        return FAIL;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteRemoteObject(callback)");
        return FAIL;
    }

    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_GET_SEC_INFO, data, reply, true);
    if (ret) {
        result = reply.ReadInt32();
        USERIDM_HILOGI(MODULE_CLIENT, "result = %{public}d", result);
    }
    return result;
}

void UserIDMProxy::AddCredential(AddCredInfo& credInfo, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return;
    }

    if (!data.WriteUint32(credInfo.authType)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint32(credInfo.authType)");
        return;
    }

    if (!data.WriteUint64(credInfo.authSubType)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint64(credInfo.authSubType)");
        return;
    }

    if (!data.WriteUInt8Vector(credInfo.token)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUInt8Vector(credInfo.token)");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteRemoteObject(callback)");
        return;
    }

    SendRequest(USERIDM_ADD_CREDENTIAL, data, reply, false);
}

void UserIDMProxy::UpdateCredential(AddCredInfo& credInfo, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return;
    }

    if (!data.WriteUint32(credInfo.authType)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint32(credInfo.authType)");
        return;
    }

    if (!data.WriteUint64(credInfo.authSubType)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint64(credInfo.authSubType)");
        return;
    }

    if (!data.WriteUInt8Vector(credInfo.token)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUInt8Vector(credInfo.token)");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteRemoteObject(callback)");
        return;
    }

    SendRequest(USERIDM_UPDATE_CREDENTIAL, data, reply, false);
}

int32_t UserIDMProxy::Cancel(uint64_t challenge)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return FAIL;
    }

    if (!data.WriteUint64(challenge)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint64(challenge)");
        return FAIL;
    }

    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_CANCEL, data, reply);
    if (ret) {
        result = reply.ReadInt32();
        USERIDM_HILOGI(MODULE_CLIENT, "result = %{public}d", result);
    }
    return result;
}

int32_t UserIDMProxy::EnforceDelUser(int32_t userId, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return FAIL;
    }

    if (!data.WriteInt32(userId)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint32(userId)");
        return FAIL;
    }

        if (!data.WriteRemoteObject(callback->AsObject())) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteRemoteObject(callback)");
        return FAIL;
    }

    int32_t result = FAIL;
    bool ret = SendRequest(USERIDM_ENFORCE_DELUSER, data, reply, false);
    if (ret) {
        result = reply.ReadInt32();
        USERIDM_HILOGI(MODULE_CLIENT, "result = %{public}d", result);
    }
    return result;
}

void UserIDMProxy::DelUser(std::vector<uint8_t> authToken, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return;
    }

    if (!data.WriteUInt8Vector(authToken)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUInt8Vector(authToken)");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteRemoteObject(callback)");
        return;
    }

    SendRequest(USERIDM_DELUSER, data, reply, false);
}

void UserIDMProxy::DelCred(uint64_t credentialId, std::vector<uint8_t> authToken, const sptr<IIDMCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserIDMProxy::GetDescriptor())) {
        USERIDM_HILOGE(MODULE_CLIENT, "write descriptor failed");
        return;
    }

    if (!data.WriteUint64(credentialId)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUint64(credentialId)");
        return;
    }

    if (!data.WriteUInt8Vector(authToken)) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteUInt8Vector(authToken)");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to WriteRemoteObject(callback)");
        return;
    }

    SendRequest(USERIDM_DELCRED, data, reply, false);
}

bool UserIDMProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync)
{
    USERIDM_HILOGD(MODULE_CLIENT, "SendRequest start");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to get remote");
        return false;
    }

    MessageOption option(MessageOption::TF_SYNC);
    if (!isSync) {
        option.SetFlags(MessageOption::TF_ASYNC);
    }

    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::UserIAM::UserIDM::SUCCESS) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to SendRequest.result = %{public}d", result);
        return false;
    }
    return true;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
