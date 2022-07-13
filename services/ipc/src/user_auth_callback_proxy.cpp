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
#include "result_code.h"
#include "user_auth_interface.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void UserAuthCallbackProxy::OnAcquireInfo(int32_t module, uint32_t acquireInfo, int32_t extraInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthCallbackProxy::GetOldDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(module)) {
        IAM_LOGE("write module failed");
        return;
    }
    if (!data.WriteUint32(acquireInfo)) {
        IAM_LOGE("write acquireInfo failed");
        return;
    }
    if (!data.WriteInt32(extraInfo)) {
        IAM_LOGE("write extraInfo failed");
        return;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_ACQUIRE_INFO, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
    }
}

void UserAuthCallbackProxy::OnAuthResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    std::vector<uint8_t> token;
    int32_t remainCounts = 0;
    int32_t freezingTime = 0;

    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token)) {
        // when auth fail token is not set
        IAM_LOGI("get token failed");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainCounts)) {
        IAM_LOGE("get remain counts failed");
    }
    if (!extraInfo.GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        IAM_LOGE("get freezing time failed");
    }

    if (!data.WriteInterfaceToken(UserAuthCallbackProxy::GetOldDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("write result failed");
        return;
    }
    if (!data.WriteUInt8Vector(token)) {
        IAM_LOGE("write token failed");
        return;
    }
    if (!data.WriteInt32(remainCounts)) {
        IAM_LOGE("write remain counts failed");
        return;
    }
    if (!data.WriteInt32(freezingTime)) {
        IAM_LOGE("write freezing time failed");
        return;
    }
    bool ret = SendRequest(UserAuthInterface::USER_AUTH_ON_RESULT, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
    }
}

void UserAuthCallbackProxy::OnIdentifyResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start");

    MessageParcel data;
    MessageParcel reply;

    int32_t userId = 0;
    std::vector<uint8_t> token;

    if (!extraInfo.GetInt32Value(Attributes::ATTR_USER_ID, userId)) {
        IAM_LOGE("get userId failed");
    }
    if (!extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token)) {
        IAM_LOGI("get token failed");
    }

    if (!data.WriteInterfaceToken(UserAuthCallbackProxy::GetOldDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("write result failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        IAM_LOGE("write userId failed");
        return;
    }
    if (!data.WriteUInt8Vector(token)) {
        IAM_LOGE("write token failed");
        return;
    }

    bool ret = SendRequest(UserAuthInterface::USER_AUTH_ON_IDENTIFY_RESULT, data, reply);
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

    uint64_t authSubType = 0;
    uint32_t remainCounts = 0;
    uint32_t freezingTime = 0;
    if (!attributes.GetUint64Value(Attributes::ATTR_PIN_SUB_TYPE, authSubType)) {
        IAM_LOGE("get authSubType failed");
    }
    if (!attributes.GetUint32Value(Attributes::ATTR_REMAIN_TIMES, remainCounts)) {
        IAM_LOGE("get remain counts failed");
    }
    if (!attributes.GetUint32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        IAM_LOGE("get freezing time failed");
    }

    if (!data.WriteInterfaceToken(GetExecutorPropertyCallbackProxy::GetOldDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(result)) {
        IAM_LOGE("write result failed");
        return;
    }
    if (!data.WriteUint64(authSubType)) {
        IAM_LOGE("write authSubType failed");
        return;
    }
    if (!data.WriteUint32(remainCounts)) {
        IAM_LOGE("write remain counts failed");
        return;
    }
    if (!data.WriteUint32(freezingTime)) {
        IAM_LOGE("write freezing time failed");
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

    if (!data.WriteInterfaceToken(SetExecutorPropertyCallbackProxy::GetOldDescriptor())) {
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