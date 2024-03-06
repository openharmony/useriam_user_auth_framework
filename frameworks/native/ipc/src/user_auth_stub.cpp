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

#include "user_auth_stub.h"

#include <algorithm>
#include <cinttypes>

#include "iam_logger.h"
#include "iam_scope_guard.h"
#include "iam_common_defines.h"
#include "user_auth_callback_proxy.h"
#include "widget_callback_proxy.h"
#include "user_auth_common_defines.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const uint32_t MAX_ATTR_COUNT = 512;
} // namespace

int32_t UserAuthStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (UserAuthStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }
    switch (code) {
        case UserAuthInterfaceCode::USER_AUTH_GET_AVAILABLE_STATUS:
            return GetAvailableStatusStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_GET_PROPERTY:
            return GetPropertyStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_SET_PROPERTY:
            return SetPropertyStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_AUTH:
            return AuthStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_AUTH_WIDGET:
            return AuthWidgetStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_AUTH_USER:
            return AuthUserStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_CANCEL_AUTH:
            return CancelAuthOrIdentifyStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_IDENTIFY:
            return IdentifyStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_CANCEL_IDENTIFY:
            return CancelAuthOrIdentifyStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_GET_VERSION:
            return GetVersionStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_NOTICE:
            return NoticeStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_REG_WIDGET_CB:
            return RegisterWidgetCallbackStub(data, reply);
        case UserAuthInterfaceCode::USER_AUTH_GET_ENROLLED_STATE:
            return GetEnrolledStateStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserAuthStub::GetAvailableStatusStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t authType;
    uint32_t authTrustLevel;
    int32_t apiVersion;

    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authTrustLevel)) {
        IAM_LOGE("failed to read authTrustLevel");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(apiVersion)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    int32_t result = GetAvailableStatus(apiVersion,
        static_cast<AuthType>(authType), static_cast<AuthTrustLevel>(authTrustLevel));
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write GetAvailableStatus result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthStub::GetPropertyStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    int32_t authType;
    std::vector<uint32_t> keys;

    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt32Vector(&keys)) {
        IAM_LOGE("failed to read attribute keys");
        return READ_PARCEL_ERROR;
    }
    std::vector<Attributes::AttributeKey> attrKeys;
    if (keys.empty()) {
        IAM_LOGE("the attribute key vector is empty");
        return GENERAL_ERROR;
    }
    if (keys.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("the attribute key vector size exceed limit");
        return GENERAL_ERROR;
    }
    attrKeys.resize(keys.size());
    std::transform(keys.begin(), keys.end(), attrKeys.begin(), [](uint32_t key) {
        return static_cast<Attributes::AttributeKey>(key);
    });

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return READ_PARCEL_ERROR;
    }
    sptr<GetExecutorPropertyCallbackInterface> callback = iface_cast<GetExecutorPropertyCallbackProxy>(obj);
    if (callback == nullptr) {
        IAM_LOGE("GetExecutorPropertyCallbackInterface is nullptr");
        return GENERAL_ERROR;
    }

    GetProperty(userId, static_cast<AuthType>(authType), attrKeys, callback);
    return SUCCESS;
}

int32_t UserAuthStub::SetPropertyStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    int32_t authType;
    std::vector<uint8_t> attr;

    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&attr)) {
        IAM_LOGE("failed to read attributes");
        return READ_PARCEL_ERROR;
    }
    Attributes attributes(attr);

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return READ_PARCEL_ERROR;
    }
    sptr<SetExecutorPropertyCallbackInterface> callback = iface_cast<SetExecutorPropertyCallbackProxy>(obj);
    if (callback == nullptr) {
        IAM_LOGE("SetExecutorPropertyCallbackInterface is nullptr");
        return GENERAL_ERROR;
    }

    SetProperty(userId, static_cast<AuthType>(authType), attributes, callback);
    return SUCCESS;
}

int32_t UserAuthStub::AuthStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    std::vector<uint8_t> challenge;
    int32_t authType;
    uint32_t authTrustLevel;
    int32_t apiVersion;

    if (!data.ReadUInt8Vector(&challenge)) {
        IAM_LOGE("failed to read challenge");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authTrustLevel)) {
        IAM_LOGE("failed to read authTrustLevel");
        return READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return READ_PARCEL_ERROR;
    }
    sptr<UserAuthCallbackInterface> callback = iface_cast<UserAuthCallbackProxy>(obj);
    if (callback == nullptr) {
        IAM_LOGE("UserAuthCallbackInterface is nullptr");
        return GENERAL_ERROR;
    }
    if (!data.ReadInt32(apiVersion)) {
        IAM_LOGE("failed to read apiVersion");
        return READ_PARCEL_ERROR;
    }

    uint64_t contextId = Auth(apiVersion, challenge, static_cast<AuthType>(authType),
        static_cast<AuthTrustLevel>(authTrustLevel), callback);
    if (!reply.WriteUint64(contextId)) {
        IAM_LOGE("failed to write AuthUser result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthStub::AuthWidgetStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    AuthParam authParam;
    WidgetParam widgetParam;
    if (!ReadWidgetParam(data, authParam, widgetParam)) {
        IAM_LOGE("failed to read widget param");
        return ResultCode::READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return ResultCode::READ_PARCEL_ERROR;
    }
    sptr<UserAuthCallbackInterface> callback = iface_cast<UserAuthCallbackProxy>(obj);
    if (callback == nullptr) {
        IAM_LOGE("UserAuthCallbackInterface is nullptr");
        return ResultCode::GENERAL_ERROR;
    }

    int32_t apiVersion;
    if (!data.ReadInt32(apiVersion)) {
        IAM_LOGE("failed to read apiVersion");
        return ResultCode::READ_PARCEL_ERROR;
    }

    uint64_t contextId = AuthWidget(apiVersion, authParam, widgetParam, callback);
    if (!reply.WriteUint64(contextId)) {
        IAM_LOGE("failed to write contextId");
        return ResultCode::WRITE_PARCEL_ERROR;
    }
    return ResultCode::SUCCESS;
}

bool UserAuthStub::ReadWidgetParam(MessageParcel &data, AuthParam &authParam, WidgetParam &widgetParam)
{
    if (!data.ReadUInt8Vector(&authParam.challenge)) {
        IAM_LOGE("failed to read challenge");
        return false;
    }
    std::vector<int32_t> atList;
    if (!data.ReadInt32Vector(&atList)) {
        IAM_LOGE("failed to read authTypeList");
        return false;
    }
    for (auto at : atList) {
        authParam.authType.push_back(static_cast<AuthType>(at));
    }

    uint32_t authTrustLevel;
    if (!data.ReadUint32(authTrustLevel)) {
        IAM_LOGE("failed to read authTrustLevel");
        return false;
    }
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(authTrustLevel);

    widgetParam.title = data.ReadString();
    widgetParam.navigationButtonText = data.ReadString();
    int32_t winMode;
    if (!data.ReadInt32(winMode)) {
        IAM_LOGE("failed to read window mode");
        return false;
    }
    widgetParam.windowMode = static_cast<WindowModeType>(winMode);
    return true;
}

int32_t UserAuthStub::AuthUserStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t userId;
    std::vector<uint8_t> challenge;
    int32_t authType;
    uint32_t authTrustLevel;

    if (!data.ReadInt32(userId)) {
        IAM_LOGE("failed to read userId");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&challenge)) {
        IAM_LOGE("failed to read challenge");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(authTrustLevel)) {
        IAM_LOGE("failed to read authTrustLevel");
        return READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return READ_PARCEL_ERROR;
    }
    sptr<UserAuthCallbackInterface> callback = iface_cast<UserAuthCallbackProxy>(obj);
    if (callback == nullptr) {
        IAM_LOGE("UserAuthCallbackInterface is nullptr");
        return GENERAL_ERROR;
    }

    uint64_t contextId = AuthUser(userId, challenge, static_cast<AuthType>(authType),
        static_cast<AuthTrustLevel>(authTrustLevel), callback);
    if (!reply.WriteUint64(contextId)) {
        IAM_LOGE("failed to write AuthUser result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthStub::IdentifyStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    std::vector<uint8_t> challenge;
    int32_t authType;

    if (!data.ReadUInt8Vector(&challenge)) {
        IAM_LOGE("failed to read challenge");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return READ_PARCEL_ERROR;
    }
    sptr<UserAuthCallbackInterface> callback = iface_cast<UserAuthCallbackProxy>(obj);
    if (callback == nullptr) {
        IAM_LOGE("UserAuthCallbackInterface is nullptr");
        return GENERAL_ERROR;
    }

    uint64_t contextId = Identify(challenge, static_cast<AuthType>(authType), callback);
    if (!reply.WriteUint64(contextId)) {
        IAM_LOGE("failed to write Identify result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthStub::CancelAuthOrIdentifyStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    uint64_t contextId;

    if (!data.ReadUint64(contextId)) {
        IAM_LOGE("failed to read contextId");
        return READ_PARCEL_ERROR;
    }

    int32_t result = CancelAuthOrIdentify(contextId);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write CancelAuthOrIdentify result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthStub::GetVersionStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t version;
    int32_t result = GetVersion(version);
    if (!reply.WriteInt32(version)) {
        IAM_LOGE("failed to write GetVersion version");
        return WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write GetVersion result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t UserAuthStub::NoticeStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t type;
    if (!data.ReadInt32(type)) {
        IAM_LOGE("failed to read type");
        return ResultCode::READ_PARCEL_ERROR;
    }
    NoticeType noticeType = static_cast<NoticeType>(type);
    if (noticeType != WIDGET_NOTICE) {
        IAM_LOGE("NoticeStub unsupport notice type");
        return ResultCode::GENERAL_ERROR;
    }
    std::string eventData = data.ReadString();

    int32_t result = Notice(noticeType, eventData);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write notice result");
        return ResultCode::WRITE_PARCEL_ERROR;
    }
    IAM_LOGI("noticeStub success");
    return ResultCode::SUCCESS;
}

int32_t UserAuthStub::RegisterWidgetCallbackStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t version;
    if (!data.ReadInt32(version)) {
        IAM_LOGE("failed to read version");
        return READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return READ_PARCEL_ERROR;
    }
    sptr<WidgetCallbackInterface> callback = iface_cast<WidgetCallbackProxy>(obj);
    if (callback == nullptr) {
        IAM_LOGE("RegisterWidgetCallbackStub is nullptr");
        return GENERAL_ERROR;
    }
    int32_t result = RegisterWidgetCallback(version, callback);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write register widget callback result");
        return WRITE_PARCEL_ERROR;
    }
    IAM_LOGI("RegisterWidgetCallbackStub success");
    return SUCCESS;
}

int32_t UserAuthStub::GetEnrolledStateStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("enter");
    ON_SCOPE_EXIT(IAM_LOGI("leave"));

    int32_t apiVersion;
    if (!data.ReadInt32(apiVersion)) {
        IAM_LOGE("failed to read apiVersion");
        return READ_PARCEL_ERROR;
    }

    int32_t authType;
    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    EnrolledState enrolledState = {};
    int32_t ret = GetEnrolledState(apiVersion, static_cast<AuthType>(authType), enrolledState);
    if (!reply.WriteInt32(ret)) {
        IAM_LOGE("failed to write ret");
        return WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteUint16(enrolledState.credentialDigest)) {
        IAM_LOGE("failed to write credentialDigest");
        return WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteUint16(enrolledState.credentialCount)) {
        IAM_LOGE("failed to write credentialCount");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS