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

#include "executor_messenger_stub.h"

#include <cinttypes>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_common_defines.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t ExecutorMessengerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("ExecutorMessengerStub::OnRemoteRequest, cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (ExecutorMessengerStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }
    switch (code) {
        case ExecutorMessengerInterface::CO_AUTH_SEND_DATA:
            return SendDataStub(data, reply);
        case ExecutorMessengerInterface::CO_AUTH_FINISH:
            return FinishStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t ExecutorMessengerStub::SendDataStub(MessageParcel &data, MessageParcel &reply)
{
    uint64_t scheduleId;
    uint64_t transNum;
    int32_t srcRole;
    int32_t dstRole;
    std::vector<uint8_t> msg;

    if (!data.ReadUint64(scheduleId)) {
        IAM_LOGE("read scheduleId failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint64(transNum)) {
        IAM_LOGE("read transNum failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(srcRole)) {
        IAM_LOGE("read srcRole failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(dstRole)) {
        IAM_LOGE("read dstRole failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&msg)) {
        IAM_LOGE("read msg failed");
        return GENERAL_ERROR;
    }

    int32_t result =
        SendData(scheduleId, transNum, static_cast<ExecutorRole>(srcRole), static_cast<ExecutorRole>(dstRole), msg);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("write SendData result failed");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t ExecutorMessengerStub::FinishStub(MessageParcel &data, MessageParcel &reply)
{
    uint64_t scheduleId;
    int32_t srcRole;
    int32_t resultCode;
    std::vector<uint8_t> attributes;

    if (!data.ReadUint64(scheduleId)) {
        IAM_LOGE("read scheduleId failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(srcRole)) {
        IAM_LOGE("read srcRole failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(resultCode)) {
        IAM_LOGE("read resultCode failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&attributes)) {
        IAM_LOGE("read attributes failed");
        return READ_PARCEL_ERROR;
    }
    auto finalResult = Common::MakeShared<Attributes>(attributes);
    IF_FALSE_LOGE_AND_RETURN_VAL(finalResult != nullptr, WRITE_PARCEL_ERROR);
    int32_t result =
        Finish(scheduleId, static_cast<ExecutorRole>(srcRole), static_cast<ResultCode>(resultCode), finalResult);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("write Finish result failed");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS