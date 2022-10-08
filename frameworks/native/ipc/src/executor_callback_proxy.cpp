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

#include "executor_callback_proxy.h"

#include "iam_logger.h"
#include "iam_common_defines.h"
#include "message_parcel.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void ExecutorCallbackProxy::OnMessengerReady(sptr<ExecutorMessengerInterface> &messenger,
    const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList)
{
    if (messenger == nullptr) {
        IAM_LOGE("messenger is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteRemoteObject(messenger->AsObject())) {
        IAM_LOGE("failed to write messenger failed");
        return;
    }
    if (!data.WriteUInt8Vector(publicKey)) {
        IAM_LOGE("failed to write publicKey");
        return;
    }
    if (!data.WriteUInt64Vector(templateIdList)) {
        IAM_LOGE("failed to write templateIdList");
        return;
    }

    bool result = SendRequest(ExecutorCallbackInterface::ON_MESSENGER_READY, data, reply);
    if (!result) {
        IAM_LOGE("send request failed");
        return;
    }
}

int32_t ExecutorCallbackProxy::OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
    const Attributes &command)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return GENERAL_ERROR;
    }
    if (!data.WriteUint64(scheduleId)) {
        IAM_LOGE("write scheduleId failed");
        return GENERAL_ERROR;
    }
    if (!data.WriteUInt8Vector(publicKey)) {
        IAM_LOGE("write publicKey failed");
        return GENERAL_ERROR;
    }
    auto attr = command.Serialize();
    if (!data.WriteUInt8Vector(attr)) {
        IAM_LOGE("write command failed");
        return GENERAL_ERROR;
    }

    bool ret = SendRequest(ExecutorCallbackInterface::ON_BEGIN_EXECUTE, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("read request result failed");
        return GENERAL_ERROR;
    }
    return result;
}

int32_t ExecutorCallbackProxy::OnEndExecute(uint64_t scheduleId, const Attributes &command)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return GENERAL_ERROR;
    }
    if (!data.WriteUint64(scheduleId)) {
        IAM_LOGE("write scheduleId failed");
        return GENERAL_ERROR;
    }
    auto attr = command.Serialize();
    if (!data.WriteUInt8Vector(attr)) {
        IAM_LOGE("write command failed");
        return GENERAL_ERROR;
    }

    bool ret = SendRequest(ExecutorCallbackInterface::ON_END_EXECUTE, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("read request result failed");
        return GENERAL_ERROR;
    }
    return result;
}

int32_t ExecutorCallbackProxy::OnSetProperty(const Attributes &properties)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return GENERAL_ERROR;
    }
    auto attr = properties.Serialize();
    if (!data.WriteUInt8Vector(attr)) {
        IAM_LOGE("write properties failed");
        return GENERAL_ERROR;
    }

    bool ret = SendRequest(ExecutorCallbackInterface::ON_SET_PROPERTY, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("read request result failed");
        return GENERAL_ERROR;
    }
    return result;
}

int32_t ExecutorCallbackProxy::OnGetProperty(const Attributes &condition, Attributes &values)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return GENERAL_ERROR;
    }

    if (!data.WriteUInt8Vector(condition.Serialize())) {
        IAM_LOGE("write condition failed");
        return GENERAL_ERROR;
    }

    bool ret = SendRequest(ExecutorCallbackInterface::ON_GET_PROPERTY, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
        return GENERAL_ERROR;
    }
    int32_t result = GENERAL_ERROR;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("read request result failed");
        return GENERAL_ERROR;
    }

    std::vector<uint8_t> attr;
    if (!reply.ReadUInt8Vector(&attr)) {
        IAM_LOGE("read reply values failed");
        return GENERAL_ERROR;
    }
    values = Attributes(attr);
    return result;
}

bool ExecutorCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("code = %{public}u", code);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, code = %{public}u, result = %{public}d", code, result);
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS