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

#include <message_parcel.h>

#include "userauth_hilog_wrapper.h"
#include "iuser_auth.h"
#include "userauth_async_stub.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
UserAuthAsyncStub::UserAuthAsyncStub(std::shared_ptr<UserAuthCallback>& impl)
{
    authCallback_ = impl;
}
UserAuthAsyncStub::UserAuthAsyncStub(std::shared_ptr<GetPropCallback>& impl)
{
    getPropCallback_ = impl;
}
UserAuthAsyncStub::UserAuthAsyncStub(std::shared_ptr<SetPropCallback>& impl)
{
    setPropCallback_ = impl;
}
int32_t UserAuthAsyncStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                           MessageOption &option)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthAsyncStub::OnRemoteRequest");

    std::u16string descripter = UserAuthAsyncStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthAsyncStub::OnRemoteRequest failed, descriptor is not matched!");
        return E_GET_POWER_SERVICE_FAILED;
    }

    switch (code) {
        case static_cast<int32_t>(IUserAuth::USER_AUTH_ACQUIRENFO):
            return onAcquireInfoStub(data, reply);
        case static_cast<int32_t>(IUserAuth::USER_AUTH_ONRESULT):
            return onResultStub(data, reply);
        case static_cast<int32_t>(IUserAuth::USER_AUTH_GETEXPORP):
            return onExecutorPropertyInfoStub(data, reply);
        case static_cast<int32_t>(IUserAuth::USER_AUTH_SETEXPORP):
            return onSetExecutorPropertyStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserAuthAsyncStub::onAcquireInfoStub(MessageParcel& data, MessageParcel& reply)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthAsyncStub OnAcquireInfoStub enter ");

    int32_t ret = SUCCESS;
    int32_t module;
    uint32_t acquireInfo;
    int32_t extraInfo;

    if (!data.ReadInt32(module)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadInt32(module).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(acquireInfo)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadUint32(acquireInfo).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(extraInfo)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadInt32(extraInfo).");
        return E_READ_PARCEL_ERROR;
    }

    this->onAcquireInfo(module, acquireInfo, extraInfo);
    if (!reply.WriteInt32(ret)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth failed to WriteInt32(ret)");
        return E_WRITE_PARCEL_ERROR;
    }

    return ret;
}

int32_t UserAuthAsyncStub::onResultStub(MessageParcel& data, MessageParcel& reply)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthAsyncStub onResultStub enter ");

    int32_t ret = SUCCESS;
    AuthResult authResult;
    std::vector<uint8_t> token;
    uint32_t remainTimes;
    uint32_t freezingTime;
    int32_t result = GENERAL_ERROR;

    if (!data.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadInt32(result).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&token)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadUInt8Vector(&token).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(remainTimes)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadUint32(remainTimes).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(freezingTime)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadUint32(freezingTime).");
        return E_READ_PARCEL_ERROR;
    }
    authResult.freezingTime = freezingTime;
    authResult.remainTimes = remainTimes;
    authResult.token.clear();
    authResult.token.assign(token.begin(), token.end());

    this->onResult(result, authResult);
    if (!reply.WriteInt32(ret)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth failed to WriteInt32(ret)");
        return E_WRITE_PARCEL_ERROR;
    }

    return ret;
}

int32_t UserAuthAsyncStub::onExecutorPropertyInfoStub(MessageParcel& data, MessageParcel& reply)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthAsyncStub onExecutorPropertyInfoStub enter ");

    int32_t ret = SUCCESS;
    int32_t result;
    uint64_t authSubType;
    uint32_t remainTimes;
    uint32_t freezingTime;
    ExecutorProperty executorProperty;

    if (!data.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadInt32(result).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint64(authSubType)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadUint64(authSubType).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(remainTimes)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadUint32(remainTimes).");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(freezingTime)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadUint32(freezingTime).");
        return E_READ_PARCEL_ERROR;
    }
    executorProperty.authSubType = static_cast<AuthSubType>(authSubType);
    executorProperty.freezingTime = freezingTime;
    executorProperty.remainTimes = remainTimes;
    executorProperty.result = static_cast<AuthSubType>(result);

    this->onExecutorPropertyInfo(executorProperty);
    if (!reply.WriteInt32(ret)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth failed to WriteInt32(ret)");
        return E_WRITE_PARCEL_ERROR;
    }

    return ret;
}

int32_t UserAuthAsyncStub::onSetExecutorPropertyStub(MessageParcel& data, MessageParcel& reply)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth onSetExecutorPropertyStub enter ");

    int32_t ret = SUCCESS;
    int32_t result = GENERAL_ERROR;

    if (!data.ReadInt32(result)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadInt32(result).");
        return E_READ_PARCEL_ERROR;
    }

    this->onSetExecutorProperty(result);

    if (!reply.WriteInt32(ret)) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth failed to WriteInt32(ret)");
        ret = E_WRITE_PARCEL_ERROR;
    }

    return ret;
}

void UserAuthAsyncStub::onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  onAcquireInfo enter");
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  module:%{public}d", module);
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  acquireInfo:%{public}d", acquireInfo);
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  extraInfo:%{public}d", extraInfo);
    if (authCallback_ == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauthAsyncStub  onAcquireInfo callback is Null");
        return ;
    }
    authCallback_->onAcquireInfo(module, acquireInfo, extraInfo);
}

void UserAuthAsyncStub::onResult(const int32_t result, const AuthResult extraInfot)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  onResult enter");
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  result:%{public}d", result);
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  remainTimes:%{public}d", extraInfot.remainTimes);
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  freezingTime:%{public}d", extraInfot.freezingTime);

    if (authCallback_ == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauthAsyncStub  onResult callback is Null");
        return ;
    }
    authCallback_->onResult(result, extraInfot);
}

void UserAuthAsyncStub::onExecutorPropertyInfo(const ExecutorProperty result)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthAsyncStub onExecutorPropertyInfo enter");

    if (getPropCallback_ == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthAsyncStub onExecutorPropertyInfo callback is Null");
        return ;
    }
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  result:%{public}d", result.result);
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  authSubType:%{public}llu", result.authSubType);
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  remainTimes:%{public}d", result.freezingTime);
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  freezingTime:%{public}d", result.freezingTime);
    getPropCallback_->onGetProperty(result);
}

void UserAuthAsyncStub::onSetExecutorProperty(const int32_t result)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "UserAuthAsyncStub onSetExecutorProperty enter");

    if (setPropCallback_ == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthAsyncStub onSetExecutorProperty callback is Null");
        return ;
    }
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauthAsyncStub  result:%{public}d", result);
    setPropCallback_->onSetProperty(result);
}
}  // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS
