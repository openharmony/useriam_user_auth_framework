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

#include "executor_callback_stub.h"

#include "executor_messenger_proxy.h"
#include "iam_common_defines.h"
#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t ExecutorCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    IAM_LOGD("cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (ExecutorCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }
    switch (code) {
        case ExecutorCallbackInterface::ON_MESSENGER_READY:
            return OnMessengerReadyStub(data, reply);
        case ExecutorCallbackInterface::ON_BEGIN_EXECUTE:
            return OnBeginExecuteStub(data, reply);
        case ExecutorCallbackInterface::ON_END_EXECUTE:
            return OnEndExecuteStub(data, reply);
        case ExecutorCallbackInterface::ON_SET_PROPERTY:
            return OnSetPropertyStub(data, reply);
        case ExecutorCallbackInterface::ON_GET_PROPERTY:
            return OnGetPropertyStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t ExecutorCallbackStub::OnMessengerReadyStub(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("failed to read remote object");
        return READ_PARCEL_ERROR;
    }
    sptr<ExecutorMessengerInterface> messenger = iface_cast<ExecutorMessengerProxy>(obj);
    if (messenger == nullptr) {
        IAM_LOGE("executor messenger is nullptr");
        return GENERAL_ERROR;
    }
    
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;

    if (!data.ReadUInt8Vector(&publicKey)) {
        IAM_LOGE("failed to read publicKey");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt64Vector(&templateIds)) {
        IAM_LOGE("failed to read templateIds");
        return READ_PARCEL_ERROR;
    }

    OnMessengerReady(messenger, publicKey, templateIds);
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnBeginExecuteStub(MessageParcel &data, MessageParcel &reply)
{
    uint64_t scheduleId;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> buffer;

    if (!data.ReadUint64(scheduleId)) {
        IAM_LOGE("failed to read scheduleId");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&publicKey)) {
        IAM_LOGE("failed to read publicKey");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&buffer)) {
        IAM_LOGE("failed to read command");
        return READ_PARCEL_ERROR;
    }
    Attributes commandAttrs(buffer);

    int32_t result = OnBeginExecute(scheduleId, publicKey, commandAttrs);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write OnBeginExecute result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnEndExecuteStub(MessageParcel &data, MessageParcel &reply)
{
    uint64_t scheduleId;
    std::vector<uint8_t> buffer;

    if (!data.ReadUint64(scheduleId)) {
        IAM_LOGE("failed to read scheduleId");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&buffer)) {
        IAM_LOGE("failed to read command");
        return READ_PARCEL_ERROR;
    }
    Attributes consumerAttr(buffer);

    int32_t result = OnEndExecute(scheduleId, consumerAttr);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write OnEndExecute result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnSetPropertyStub(MessageParcel &data, MessageParcel &reply)
{
    std::vector<uint8_t> buffer;
    if (!data.ReadUInt8Vector(&buffer)) {
        IAM_LOGE("failed to read properties");
        return READ_PARCEL_ERROR;
    }
    Attributes properties(buffer);

    int32_t result = OnSetProperty(properties);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write OnSetProperty result");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnGetPropertyStub(MessageParcel &data, MessageParcel &reply)
{
    std::vector<uint8_t> buffer;
    if (!data.ReadUInt8Vector(&buffer)) {
        IAM_LOGE("failed to read conditions");
        return READ_PARCEL_ERROR;
    }
    Attributes conditions(buffer);
    Attributes values;

    int32_t result = OnGetProperty(conditions, values);
    if (!reply.WriteInt32(result)) {
        IAM_LOGE("failed to write OnGetProperty result");
        return WRITE_PARCEL_ERROR;
    }

    std::vector<uint8_t> replyBuffer = values.Serialize();
    if (!reply.WriteUInt8Vector(replyBuffer)) {
        IAM_LOGE("failed to write replyBuffer");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS