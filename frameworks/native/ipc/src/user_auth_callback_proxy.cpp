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

#include "user_auth_callback_proxy.h"

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "user_auth_interface.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void UserAuthCallbackProxy::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("write result failed");
        return;
    }
    auto buffer = extraInfo.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("write buffer failed");
        return;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_ON_RESULT, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
    }
}

void UserAuthCallbackProxy::OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(module)) {
        IAM_LOGE("write module failed");
        return;
    }
    if (!data.WriteInt32(acquireInfo)) {
        IAM_LOGE("write acquireInfo failed");
        return;
    }
    auto buffer = extraInfo.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("write buffer failed");
        return;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_ACQUIRE_INFO, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
    }
}

bool UserAuthCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, result = %{public}d", result);
        return false;
    }
    IAM_LOGI("end");
    return true;
}

void GetExecutorPropertyCallbackProxy::OnGetExecutorPropertyResult(int32_t result, const Attributes &attributes)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetExecutorPropertyCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("write result failed");
        return;
    }
    auto buffer = attributes.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("write buffer failed");
        return;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_GET_EX_PROP, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
    }
}

bool GetExecutorPropertyCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, result = %{public}d", result);
        return false;
    }
    IAM_LOGI("end");
    return true;
}

void SetExecutorPropertyCallbackProxy::OnSetExecutorPropertyResult(int32_t result)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(SetExecutorPropertyCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("write result failed");
        return;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_SET_EX_PROP, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
    }
}

bool SetExecutorPropertyCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, result = %{public}d", result);
        return false;
    }
    IAM_LOGI("end");
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS