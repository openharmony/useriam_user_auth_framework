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

#include "coauth_stub.h"
#include <cinttypes>
#include <message_parcel.h>
#include "coauth_hilog_wrapper.h"
#include "coauth_errors.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
int32_t CoAuthStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                    MessageParcel &reply, MessageOption &option)
{
    COAUTH_HILOGD(MODULE_SERVICE, "CoAuthStub::OnRemoteRequest, cmd = %{public}u, flags= %{public}d",
                  code, option.GetFlags());
    std::u16string descripter = CoAuthStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        COAUTH_HILOGE(MODULE_SERVICE, "descriptor is not matched");
        return E_GET_POWER_SERVICE_FAILED;
    }

    switch (code) {
        case static_cast<int32_t>(ICoAuth::COAUTH_EXECUTOR_REGIST):
            return RegisterStub(data, reply);
        case static_cast<int32_t>(ICoAuth::COAUTH_QUERY_STATUS):
            return QueryStatusStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

void CoAuthStub::ReadAuthExecutor(AuthResPool::AuthExecutor &executorInfo, MessageParcel& data)
{
    int32_t authType = data.ReadInt32();
    executorInfo.SetAuthType(static_cast<AuthType>(authType));
    COAUTH_HILOGD(MODULE_SERVICE, "ReadInt32,authType:%{public}d", authType);

    uint64_t authAbility = data.ReadUint64();
    executorInfo.SetAuthAbility(authAbility);
    COAUTH_HILOGD(MODULE_SERVICE, "ReadInt64,authAbility:%{public}" PRIu64, authAbility);

    int32_t executorSecLevel = data.ReadInt32();
    executorInfo.SetExecutorSecLevel(static_cast<ExecutorSecureLevel>(executorSecLevel));
    COAUTH_HILOGD(MODULE_SERVICE, "ReadInt32,executorSecLevel:%{public}d", executorSecLevel);

    int32_t executorType = data.ReadInt32();
    executorInfo.SetExecutorType(static_cast<ExecutorType>(executorType));
    COAUTH_HILOGD(MODULE_SERVICE, "ReadInt32,executorSecLevel:%{public}d", executorSecLevel);

    std::vector<uint8_t> publicKey;
    data.ReadUInt8Vector(&publicKey);
    executorInfo.SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    data.ReadUInt8Vector(&deviceId);
    executorInfo.SetDeviceId(deviceId);
}

int32_t CoAuthStub::RegisterStub(MessageParcel& data, MessageParcel& reply)
{
    std::shared_ptr<AuthResPool::AuthExecutor> executorInfo = std::make_shared<AuthResPool::AuthExecutor>();
    ReadAuthExecutor(*executorInfo, data);
    sptr<AuthResPool::IExecutorCallback> callback = iface_cast<AuthResPool::IExecutorCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "read IExecutorCallback is nullptr");
        return FAIL;
    }
    uint64_t ret = Register(executorInfo, callback);
    if (!reply.WriteUint64(ret)) {
        COAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(ret)");
        return FAIL;
    }
    return SUCCESS;
}

int32_t CoAuthStub::QueryStatusStub(MessageParcel& data, MessageParcel& reply)
{
    AuthResPool::AuthExecutor executorInfo;
    ReadAuthExecutor(executorInfo, data);
    sptr<AuthResPool::IQueryCallback> callback = iface_cast<AuthResPool::IQueryCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "read IQueryCallback is nullptr");
        return FAIL;
    }

    QueryStatus(executorInfo, callback);
    return SUCCESS;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
