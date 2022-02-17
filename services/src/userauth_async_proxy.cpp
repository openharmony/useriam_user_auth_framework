/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "userauth_async_proxy.h"
#include "userauth_hilog_wrapper.h"
#include "iuser_auth.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
void UserAuthAsyncProxy::onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "userauthAsyncProxy onAcquireInfo enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(UserAuthAsyncProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_SERVICE, "userauth write descriptor failed!");
        return;
    }
    if (!data.WriteInt32(module)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(module).");
        return;
    }
    if (!data.WriteUint32(acquireInfo)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteUint32(acquireInfo).");
        return;
    }
    if (!data.WriteInt32(extraInfo)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(extraInfo).");
        return;
    }

    bool ret = SendRequest(IUserAuth::USER_AUTH_ACQUIRENFO, data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        USERAUTH_HILOGE(MODULE_SERVICE, "userauth result = %{public}d", result);
    }
    return;
}

void UserAuthAsyncProxy::onResult(const int32_t result, const AuthResult extraInfo)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "userauthAsyncProxy onResult enter");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserAuthAsyncProxy::GetDescriptor())) {
        USERAUTH_HILOGI(MODULE_SERVICE, "userauth write descriptor failed!");
        return;
    }
    if (!data.WriteInt32(result)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(result).");
        return;
    }
    if (!data.WriteUInt8Vector(extraInfo.token)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteUInt8Vector(extraInfo.token).");
        return;
    }
    if (!data.WriteUint32(extraInfo.remainTimes)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteUint32(extraInfo.remainTimes).");
        return;
    }
    if (!data.WriteUint32(extraInfo.freezingTime)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteUint32(extraInfo.freezingTime).");
        return;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_ONRESULT, data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        USERAUTH_HILOGE(MODULE_SERVICE, "userauth result = %{public}d", result);
    }
    return;
}

void UserAuthAsyncProxy::onExecutorPropertyInfo(const ExecutorProperty result)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "userauthAsyncProxy onExecutorPropertyInfo enter");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserAuthAsyncProxy::GetDescriptor())) {
        USERAUTH_HILOGI(MODULE_SERVICE, "userauth write descriptor failed!");
        return;
    }
    if (!data.WriteInt32(result.result)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(result.result).");
        return;
    }
    if (!data.WriteUint64(result.authSubType)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteUint64(result.authSubType).");
        return;
    }
    if (!data.WriteUint32(result.remainTimes)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteUint32(result.remainTimes).");
        return;
    }
    if (!data.WriteUint32(result.freezingTime)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteUint32(result.freezingTime).");
        return;
    }
    bool ret = SendRequest(IUserAuth::USER_AUTH_GETEXPORP, data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        USERAUTH_HILOGE(MODULE_SERVICE, "userauth result = %{public}d", result);
    }
    return;
}

void UserAuthAsyncProxy::onSetExecutorProperty(const int32_t result)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "userauthAsyncProxy onSetExecutorProperty enter");

    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(UserAuthAsyncProxy::GetDescriptor())) {
        USERAUTH_HILOGE(MODULE_SERVICE, "userauth write descriptor failed!");
        return;
    }
    if (!data.WriteInt32(result)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(result).");
        return;
    }

    bool ret = SendRequest(IUserAuth::USER_AUTH_SETEXPORP, data, reply);
    if (ret) {
        int32_t result = reply.ReadInt32();
        USERAUTH_HILOGE(MODULE_SERVICE, "userauth result = %{public}d", result);
    }

    return;
}

bool UserAuthAsyncProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "userauthAsyncProxy SendRequest enter");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "userauth failed to get remote.");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::UserIAM::UserAuth::SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "userauth failed to SendRequest.result = %{public}d", result);
        return false;
    }
    USERAUTH_HILOGD(MODULE_SERVICE, "userauthAsyncProxy SendRequest end");
    return true;
}
}  // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS
