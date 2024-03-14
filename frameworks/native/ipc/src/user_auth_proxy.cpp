/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const uint64_t BAD_CONTEXT_ID = 0;
    const uint32_t MAX_ATTR_COUNT = 512;
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

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_GET_AVAILABLE_STATUS, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send get available status IPC request");
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
    if (keys.empty()) {
        IAM_LOGE("the attribute key vector is empty");
        return;
    }
    if (keys.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("the attribute key vector size exceed limit");
        return;
    }
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

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_GET_PROPERTY, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send get property IPC request");
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

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_SET_PROPERTY, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send set property IPC request");
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
    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_AUTH, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send user auth IPC request");
        return BAD_CONTEXT_ID;
    }
    uint64_t result = BAD_CONTEXT_ID;
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

uint64_t UserAuthProxy::AuthWidget(int32_t apiVersion, const AuthParam &authParam,
    const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback)
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

    if (!WriteWidgetParam(data, authParam, widgetParam)) {
        IAM_LOGE("failed to write widget param");
        return BAD_CONTEXT_ID;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return BAD_CONTEXT_ID;
    }

    if (!data.WriteInt32(apiVersion)) {
        IAM_LOGE("failed to write apiVersion");
        return BAD_CONTEXT_ID;
    }

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_AUTH_WIDGET, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send auth widget IPC request");
        return BAD_CONTEXT_ID;
    }
    uint64_t result = BAD_CONTEXT_ID;
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
    }
    return result;
}

bool UserAuthProxy::WriteWidgetParam(MessageParcel &data, const AuthParam &authParam, const WidgetParam &widgetParam)
{
    if (!data.WriteUInt8Vector(authParam.challenge)) {
        IAM_LOGE("failed to write challenge");
        return false;
    }
    std::vector<int32_t> atList;
    for (auto at : authParam.authType) {
        atList.push_back(static_cast<int32_t>(at));
    }
    if (!data.WriteInt32Vector(atList)) {
        IAM_LOGE("failed to write authTypeList");
        return false;
    }
    if (!data.WriteUint32(authParam.authTrustLevel)) {
        IAM_LOGE("failed to write authTrustLevel");
        return false;
    }

    if (!data.WriteString(widgetParam.title)) {
        IAM_LOGE("failed to write title");
        return false;
    }
    if (!data.WriteString(widgetParam.navigationButtonText)) {
        IAM_LOGE("failed to write navigation button text");
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(widgetParam.windowMode))) {
        IAM_LOGE("failed to write window mode");
        return false;
    }
    return true;
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

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_AUTH_USER, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send auth user IPC request");
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

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_IDENTIFY, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send auth identify IPC request");
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

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_CANCEL_AUTH, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send cancel auth IPC request");
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

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_GET_VERSION, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send get version IPC request");
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

int32_t UserAuthProxy::Notice(NoticeType noticeType, const std::string &eventData)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return ResultCode::WRITE_PARCEL_ERROR;
    }

    int32_t type = static_cast<int32_t>(noticeType);
    if (!data.WriteInt32(type)) {
        IAM_LOGE("failed to write noticeType");
        return ResultCode::WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(eventData)) {
        IAM_LOGE("failed to write eventData");
        return ResultCode::WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_NOTICE, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send user notice IPC request");
        return ResultCode::GENERAL_ERROR;
    }
    int32_t result = ResultCode::GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return ResultCode::READ_PARCEL_ERROR;
    }
    return result;
}

int32_t UserAuthProxy::RegisterWidgetCallback(int32_t version, sptr<WidgetCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return GENERAL_ERROR;
    }

    if (!data.WriteInt32(version)) {
        IAM_LOGE("failed to write version");
        return WRITE_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return GENERAL_ERROR;
    }

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_REG_WIDGET_CB, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send register widget callback IPC request");
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    return result;
}

int32_t UserAuthProxy::GetEnrolledState(int32_t apiVersion, AuthType authType, EnrolledState &enrolledState)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }

    if (!data.WriteInt32(apiVersion)) {
        IAM_LOGE("failed to write apiVersion");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(authType)) {
        IAM_LOGE("failed to write authType");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_GET_ENROLLED_STATE, data, reply);
    if (!ret) {
        IAM_LOGE("get enrolled state failed to send request");
        return GENERAL_ERROR;
    }

    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return GENERAL_ERROR;
    }
    if (result != SUCCESS) {
        IAM_LOGE("failed to get enrolled state");
        return result;
    }
    uint16_t credentialDigest;
    if (!reply.ReadUint16(credentialDigest)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    uint16_t credentialCount;
    if (!reply.ReadUint16(credentialCount)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    enrolledState.credentialDigest = credentialDigest;
    enrolledState.credentialCount = credentialCount;
    return SUCCESS;
}

int32_t UserAuthProxy::RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
    const sptr<AuthEventListenerInterface> &listener)
{
    if (listener == nullptr) {
        IAM_LOGE("listener is nullptr");
        return GENERAL_ERROR;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }

    std::vector<int32_t> authTypeList;
    for (auto &iter : authType) {
        authTypeList.emplace_back(static_cast<int32_t>(iter));
    }

    if (!data.WriteInt32Vector(authTypeList)) {
        IAM_LOGE("failed to write authType");
        return WRITE_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(listener->AsObject())) {
        IAM_LOGE("failed to write listener");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_REG_EVENT_LISTENER, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send register event listener callback IPC request");
        return GENERAL_ERROR;
    }

    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    return result;
}

int32_t UserAuthProxy::UnRegistUserAuthSuccessEventListener(const sptr<AuthEventListenerInterface> &listener)
{
    if (listener == nullptr) {
        IAM_LOGE("listener is nullptr");
        return GENERAL_ERROR;
    }

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(listener->AsObject())) {
        IAM_LOGE("failed to write listener");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(UserAuthInterfaceCode::USER_AUTH_UNREG_EVENT_LISTENER, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send register event listener callback IPC request");
        return GENERAL_ERROR;
    }

    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    return result;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS