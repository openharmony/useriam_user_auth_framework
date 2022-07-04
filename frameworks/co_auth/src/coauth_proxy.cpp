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

#include "coauth_proxy.h"

#include <cinttypes>
#include <message_parcel.h>
#include <string_ex.h>

#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
uint32_t CoAuthProxy::WriteAuthExecutor(AuthExecutor &executorInfo, MessageParcel &data)
{
    AuthType authType;
    executorInfo.GetAuthType(authType);
    if (!data.WriteInt32(authType)) {
        return FAIL;
    }
    IAM_LOGD("WriteInt32,authType:%{public}d", authType);

    uint64_t authAbility;
    executorInfo.GetAuthAbility(authAbility);
    if (!data.WriteUint64(authAbility)) {
        return FAIL;
    }
    IAM_LOGD("WriteUint64,authAbility:%{public}" PRIu64, authAbility);

    ExecutorSecureLevel executorSecLevel;
    executorInfo.GetExecutorSecLevel(executorSecLevel);
    if (!data.WriteInt32(executorSecLevel)) {
        return FAIL;
    }
    IAM_LOGD("WriteInt32,executorSecLevel:%{public}d", executorSecLevel);

    ExecutorType executorType;
    executorInfo.GetExecutorType(executorType);
    if (!data.WriteInt32(executorType)) {
        return FAIL;
    }
    IAM_LOGD("WriteInt32,executorType:%{public}d", executorType);

    std::vector<uint8_t> publicKey;
    executorInfo.GetPublicKey(publicKey);
    if (!data.WriteUInt8Vector(publicKey)) {
        return FAIL;
    }

    std::vector<uint8_t> deviceId;
    executorInfo.GetDeviceId(deviceId);
    if (!data.WriteUInt8Vector(deviceId)) {
        return FAIL;
    }
    return SUCCESS;
}

uint64_t CoAuthProxy::Register(std::shared_ptr<AuthExecutor> executorInfo,
    const sptr<IExecutorCallback> &callback)
{
    IAM_LOGD("Register start");
    if (executorInfo == nullptr || callback == nullptr) {
        IAM_LOGE("executorInfo or callback is nullptr");
        return 0;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(CoAuthProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return 0;
    }
    if (WriteAuthExecutor(*executorInfo, data) == FAIL) {
        IAM_LOGE("write executorInfo failed");
        return 0;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        IAM_LOGE("write callback filed");
        return 0;
    }
    uint64_t result = 0;
    bool ret = SendRequest(ICoAuth::COAUTH_EXECUTOR_REGIST, data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
        return 0;
    }
    if (!reply.ReadUint64(result)) {
        IAM_LOGE("read result failed");
        return 0;
    }
    return result;
}

bool CoAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync)
{
    IAM_LOGD("CoauthProxy: SendRequest start");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(isSync ? MessageOption::TF_SYNC : MessageOption::TF_ASYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS