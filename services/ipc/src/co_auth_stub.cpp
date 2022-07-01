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

#include "co_auth_stub.h"

#include <cinttypes>

#include "executor_callback_proxy.h"
#include "iam_logger.h"
#include "result_code.h"
#include "string_ex.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t CoAuthStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGD("CoAuthStub::OnRemoteRequest, cmd = %{public}u, flags = %{public}d", code, option.GetFlags());
    if (CoAuthStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("descriptor is not matched");
        return FAIL;
    }
    switch (code) {
        case CoAuth::CO_AUTH_EXECUTOR_REGISTER:
            return ExecutorRegisterStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
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
    sptr<ExecutorCallback> callback = new (std::nothrow) ExecutorCallbackProxy(obj);
    if (callback == nullptr) {
        IAM_LOGE("executor callback is nullptr");
        return FAIL;
    }

    uint64_t executorIndex = ExecutorRegister(executorInfo, callback);
    if (executorIndex == INVALID_EXECUTOR_INDEX) {
        IAM_LOGE("executor register failed");
        return FAIL;
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
    uint64_t authAbility;
    int32_t executorSecLevel;
    int32_t executorType;
    std::vector<uint8_t> deviceId;

    if (!data.ReadInt32(authType)) {
        IAM_LOGE("read authType failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUint64(authAbility)) {
        IAM_LOGE("read authAbility failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(executorSecLevel)) {
        IAM_LOGE("read executorSecLevel failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(executorType)) {
        IAM_LOGE("read executorType failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&executorInfo.publicKey)) {
        IAM_LOGE("read publicKey failed");
        return READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&deviceId)) {
        IAM_LOGE("read deviceId failed");
        return READ_PARCEL_ERROR;
    }

    executorInfo.authType = static_cast<AuthType>(static_cast<uint32_t>(authType));
    executorInfo.executorRole = static_cast<ExecutorRole>(static_cast<uint32_t>(executorType));
    executorInfo.executorSensorHint = 0;
    executorInfo.executorMatcher = 0;
    executorInfo.esl = static_cast<ExecutorSecureLevel>(static_cast<uint32_t>(executorSecLevel));
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS