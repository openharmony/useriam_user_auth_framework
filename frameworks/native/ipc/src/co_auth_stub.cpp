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

#include "co_auth_stub.h"

#include <cinttypes>

#include "executor_callback_proxy.h"
#include "iam_logger.h"
#include "iam_common_defines.h"
#include "string_ex.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

// When true is passed into IRemoteStub, sa will process request serially.
CoAuthStub::CoAuthStub() : IRemoteStub(true) {};

int32_t CoAuthStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGD("CoAuthStub::OnRemoteRequest, cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (CoAuthStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return GENERAL_ERROR;
    }
    switch (code) {
        case CoAuthInterfaceCode::CO_AUTH_EXECUTOR_REGISTER:
            return ExecutorRegisterStub(data, reply);
        case CoAuthInterfaceCode::CO_AUTH_EXECUTOR_UNREGISTER:
            return ExecutorUnregisterStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t CoAuthStub::ExecutorUnregisterStub(MessageParcel &data, MessageParcel &reply)
{
    uint64_t executorIndex;
    if (!data.ReadUint64(executorIndex)) {
        IAM_LOGE("failed to read executorIndex");
        return GENERAL_ERROR;
    }

    ExecutorUnregister(executorIndex);
    return SUCCESS;
}

int32_t CoAuthStub::ExecutorRegisterStub(MessageParcel &data, MessageParcel &reply)
{
    ExecutorRegisterInfo executorInfo = {};
    if (ReadExecutorRegisterInfo(executorInfo, data) != SUCCESS) {
        IAM_LOGE("read executorInfo failed");
        return READ_PARCEL_ERROR;
    }
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        IAM_LOGE("read remote object failed");
        return READ_PARCEL_ERROR;
    }
    sptr<ExecutorCallbackInterface> callback(new (std::nothrow) ExecutorCallbackProxy(obj));
    if (callback == nullptr) {
        IAM_LOGE("executor callback is nullptr");
        return GENERAL_ERROR;
    }

    uint64_t executorIndex = ExecutorRegister(executorInfo, callback);
    if (executorIndex == INVALID_EXECUTOR_INDEX) {
        IAM_LOGE("executor register failed");
        return GENERAL_ERROR;
    }
    if (!reply.WriteUint64(executorIndex)) {
        IAM_LOGE("write ExecutorRegister result failed");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

int32_t CoAuthStub::ReadExecutorRegisterInfo(ExecutorRegisterInfo &executorInfo, MessageParcel &data)
{
    int32_t authType;
    int32_t executorRole;
    int32_t esl;

    if (!data.ReadInt32(authType)) {
        IAM_LOGE("failed to read authType");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(executorRole)) {
        IAM_LOGE("failed to read executorRole");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(executorInfo.executorSensorHint)) {
        IAM_LOGE("failed to read executorSensorHint");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(executorInfo.executorMatcher)) {
        IAM_LOGE("failed to read executorMatcher");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(esl)) {
        IAM_LOGE("failed to read esl");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(executorInfo.maxTemplateAcl)) {
        IAM_LOGE("failed to read esl");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&executorInfo.publicKey)) {
        IAM_LOGE("failed to read publicKey");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadString(executorInfo.deviceUdid)) {
        IAM_LOGE("failed to read publicKey");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&executorInfo.signedRemoteExecutorInfo)) {
        IAM_LOGE("failed to read publicKey");
        return READ_PARCEL_ERROR;
    }

    executorInfo.authType = static_cast<AuthType>(authType);
    executorInfo.executorRole = static_cast<ExecutorRole>(executorRole);
    executorInfo.esl = static_cast<ExecutorSecureLevel>(esl);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS