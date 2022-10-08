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

#include "executor_messenger_proxy.h"

#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ExecutorMessengerProxy::ExecutorMessengerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ExecutorMessengerInterface>(impl)
{
}

int32_t ExecutorMessengerProxy::SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole,
    ExecutorRole dstRole, const std::vector<uint8_t> &msg)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(ExecutorMessengerProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(scheduleId)) {
        IAM_LOGE("failed to write scheduleId");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(transNum)) {
        IAM_LOGE("failed to write transNum");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(srcRole)) {
        IAM_LOGE("failed to write srcRole");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(dstRole)) {
        IAM_LOGE("failed to write dstRole");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUInt8Vector(msg)) {
        IAM_LOGE("failed to write msg");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(ExecutorMessengerInterface::CO_AUTH_SEND_DATA, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
        return GENERAL_ERROR;
    }
    int32_t result = 0;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    return result;
}

int32_t ExecutorMessengerProxy::Finish(uint64_t scheduleId, ExecutorRole srcRole, ResultCode resultCode,
    const std::shared_ptr<Attributes> &finalResult)
{
    if (finalResult == nullptr) {
        IAM_LOGE("finalResult is nullptr");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(ExecutorMessengerProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(scheduleId)) {
        IAM_LOGE("failed to write scheduleId");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(srcRole)) {
        IAM_LOGE("failed to write srcRole");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(resultCode)) {
        IAM_LOGE("failed to write resultCode");
        return WRITE_PARCEL_ERROR;
    }
    std::vector<uint8_t> buffer = finalResult->Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("failed to write finalResult");
        return WRITE_PARCEL_ERROR;
    }

    bool ret = SendRequest(ExecutorMessengerInterface::CO_AUTH_FINISH, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
        return GENERAL_ERROR;
    }
    int32_t result = 0;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return READ_PARCEL_ERROR;
    }
    return result;
}

bool ExecutorMessengerProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS