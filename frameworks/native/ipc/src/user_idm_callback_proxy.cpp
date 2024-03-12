/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "user_idm_callback_proxy.h"

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "user_idm_interface.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void IdmCallbackProxy::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(IdmCallbackProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("failed to write result");
        return;
    }
    auto buffer = extraInfo.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("failed to write buffer");
        return;
    }

    bool ret = SendRequest(IdmCallbackInterfaceCode::IDM_CALLBACK_ON_RESULT, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}

void IdmCallbackProxy::OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(IdmCallbackProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteInt32(module)) {
        IAM_LOGE("failed to write module");
        return;
    }
    if (!data.WriteInt32(acquireInfo)) {
        IAM_LOGE("failed to write acquire");
        return;
    }
    auto buffer = extraInfo.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("failed to write buffer");
        return;
    }

    bool ret = SendRequest(IdmCallbackInterfaceCode::IDM_CALLBACK_ON_ACQUIRE_INFO, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}

bool IdmCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("failed to send request, result = %{public}d", result);
        return false;
    }

    IAM_LOGI("end");
    return true;
}

void IdmGetCredentialInfoProxy::OnCredentialInfos(const std::vector<CredentialInfo> &credInfoList)
{
    IAM_LOGI("start, cred info vector size: %{public}zu", credInfoList.size());

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(IdmGetCredentialInfoProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteUint32(credInfoList.size())) {
        IAM_LOGE("failed to write credInfoList size");
        return;
    }
    for (const auto &info : credInfoList) {
        if (!data.WriteUint64(info.credentialId)) {
            IAM_LOGE("failed to write credentialId");
            return;
        }
        if (!data.WriteInt32(info.authType)) {
            IAM_LOGE("failed to write authType");
            return;
        }
        if (!data.WriteInt32(info.pinType.value_or(static_cast<PinSubType>(0)))) {
            IAM_LOGE("failed to write pinSubType");
            return;
        }
        if (!data.WriteUint64(info.templateId)) {
            IAM_LOGE("failed to write templateId");
            return;
        }
    }

    bool ret = SendRequest(IdmGetCredInfoCallbackInterfaceCode::ON_GET_INFO, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}

bool IdmGetCredentialInfoProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("failed to send request result = %{public}d", result);
        return false;
    }

    IAM_LOGI("end");
    return true;
}

ResultCode IdmGetSecureUserInfoProxy::WriteSecureUserInfo(MessageParcel &data, const SecUserInfo &secUserInfo)

{
    IAM_LOGI("start");
    if (!data.WriteInterfaceToken(IdmGetSecureUserInfoProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(secUserInfo.secureUid)) {
        IAM_LOGE("failed to write secureUid");
        return WRITE_PARCEL_ERROR;
    }
    uint32_t enrolledInfoLen = secUserInfo.enrolledInfo.size();
    IAM_LOGI("write enrolled info vector len: %{public}u", enrolledInfoLen);
    if (!data.WriteUint32(enrolledInfoLen)) {
        IAM_LOGE("failed to write enrolledInfoLen");
        return WRITE_PARCEL_ERROR;
    }
    for (const auto &info : secUserInfo.enrolledInfo) {
        if (!data.WriteInt32(info.authType)) {
            IAM_LOGE("failed to write authType");
            return WRITE_PARCEL_ERROR;
        }
        if (!data.WriteUint64(info.enrolledId)) {
            IAM_LOGE("failed to write enrolledId");
            return WRITE_PARCEL_ERROR;
        }
    }
    return SUCCESS;
}

void IdmGetSecureUserInfoProxy::OnSecureUserInfo(const SecUserInfo &secUserInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;
    if (WriteSecureUserInfo(data, secUserInfo) != SUCCESS) {
        IAM_LOGE("WriteSecureUserInfo fail");
        return;
    }

    bool ret = SendRequest(IdmGetSecureUserInfoCallbackInterfaceCode::ON_GET_SEC_INFO, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
    }
}

bool IdmGetSecureUserInfoProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("failed to get remote");
        return false;
    }
    MessageOption option(MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != SUCCESS) {
        IAM_LOGE("failed to send request result = %{public}d", result);
        return false;
    }

    IAM_LOGI("end");
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
