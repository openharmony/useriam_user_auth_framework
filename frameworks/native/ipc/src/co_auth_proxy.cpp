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

#include "co_auth_proxy.h"

#include <cinttypes>

#include "iam_common_defines.h"
#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
CoAuthProxy::CoAuthProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<CoAuthInterface>(impl)
{
}

int32_t CoAuthProxy::WriteExecutorInfo(const ExecutorRegisterInfo &info, MessageParcel &data)
{
    if (!data.WriteInt32(info.authType)) {
        IAM_LOGE("failed to write authType");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(info.executorRole)) {
        IAM_LOGE("failed to write executorRole");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint32(info.executorSensorHint)) {
        IAM_LOGE("failed to write executorSensorHint");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint32(info.executorMatcher)) {
        IAM_LOGE("failed to write executorMatcher");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint32(info.esl)) {
        IAM_LOGE("failed to write esl");
        return WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUInt8Vector(info.publicKey)) {
        IAM_LOGE("failed to write publicKey");
        return WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

uint64_t CoAuthProxy::ExecutorRegister(const ExecutorRegisterInfo &info, sptr<ExecutorCallbackInterface> &callback)
{
    IAM_LOGI("start");
    const uint64_t BAD_CONTEXT_ID = 0;
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(CoAuthProxy::GetDescriptor())) {
        IAM_LOGE("failed to write descriptor");
        return BAD_CONTEXT_ID;
    }
    if (WriteExecutorInfo(info, data) != SUCCESS) {
        IAM_LOGE("failed to write executor info");
        return BAD_CONTEXT_ID;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("failed to write callback");
        return BAD_CONTEXT_ID;
    }
    
    bool ret = SendRequest(CoAuthInterface::CO_AUTH_EXECUTOR_REGISTER, data, reply);
    if (!ret) {
        IAM_LOGE("failed to send request");
        return BAD_CONTEXT_ID;
    }
    uint64_t result = 0;
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("failed to read result");
        return BAD_CONTEXT_ID;
    }
    return result;
}

bool CoAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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