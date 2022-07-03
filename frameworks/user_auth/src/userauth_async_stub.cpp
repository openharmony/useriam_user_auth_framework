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

#include "userauth_async_stub.h"

#include <cinttypes>
#include <message_parcel.h>

#include "iam_logger.h"
#include "iam_ptr.h"
#include "iuser_auth.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
UserAuthAsyncStub::UserAuthAsyncStub(std::shared_ptr<UserAuthCallback> &impl)
    : authCallback_(impl),
      iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
}

UserAuthAsyncStub::UserAuthAsyncStub(std::shared_ptr<UserIdentifyCallback> &impl)
    : identifyCallback_(impl),
      iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("UserAuth InnerKit"))
{
}

UserAuthAsyncStub::UserAuthAsyncStub(std::shared_ptr<GetPropCallback> &impl) : getPropCallback_(impl)
{
}

UserAuthAsyncStub::UserAuthAsyncStub(std::shared_ptr<SetPropCallback> &impl) : setPropCallback_(impl)
{
}

int32_t UserAuthAsyncStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    IAM_LOGD("UserAuthAsyncStub OnRemoteRequest start");

    std::u16string descripter = UserAuthAsyncStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        IAM_LOGE("UserAuthAsyncStub::OnRemoteRequest failed, descriptor is not matched");
        return E_GET_POWER_SERVICE_FAILED;
    }

    switch (code) {
        case static_cast<int32_t>(IUserAuth::USER_AUTH_ACQUIRE_INFO):
            return onAcquireInfoStub(data, reply);
        case static_cast<int32_t>(IUserAuth::USER_AUTH_ON_RESULT):
            return onAuthResultStub(data, reply);
        case static_cast<int32_t>(IUserAuth::USER_AUTH_ON_IDENTIFY_RESULT):
            return onIdentifyResultStub(data, reply);
        case static_cast<int32_t>(IUserAuth::USER_AUTH_GET_EX_PROP):
            return onExecutorPropertyInfoStub(data, reply);
        case static_cast<int32_t>(IUserAuth::USER_AUTH_SET_EX_PROP):
            return onSetExecutorPropertyStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserAuthAsyncStub::onAcquireInfoStub(MessageParcel& data, MessageParcel& reply)
{
    IAM_LOGD("UserAuthAsyncStub OnAcquireInfoStub start");

    int32_t module;
    uint32_t acquireInfo;
    int32_t extraInfo;

    if (!data.ReadInt32(module)) {
        IAM_LOGE("failed to read module");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(acquireInfo)) {
        IAM_LOGE("failed to read acquireInfo");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(extraInfo)) {
        IAM_LOGE("failed to read extraInfo");
        return E_READ_PARCEL_ERROR;
    }

    this->onAcquireInfo(module, acquireInfo, extraInfo);
    if (!reply.WriteInt32(SUCCESS)) {
        IAM_LOGE("failed to write success");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserAuthAsyncStub::onAuthResultStub(MessageParcel& data, MessageParcel& reply)
{
    IAM_LOGD("UserAuthAsyncStub onResultStub start");

    AuthResult authResult;
    std::vector<uint8_t> token;
    uint32_t remainTimes;
    uint32_t freezingTime;
    int32_t result;

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&token)) {
        IAM_LOGE("failed to read token");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(remainTimes)) {
        IAM_LOGE("failed to read remainTimes");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(freezingTime)) {
        IAM_LOGE("failed to read freezingTime");
        return E_READ_PARCEL_ERROR;
    }
    authResult.freezingTime = freezingTime;
    authResult.remainTimes = remainTimes;
    authResult.token.clear();
    authResult.token.assign(token.begin(), token.end());

    this->onAuthResult(result, authResult);
    if (!reply.WriteInt32(SUCCESS)) {
        IAM_LOGE("failed to write success");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserAuthAsyncStub::onIdentifyResultStub(MessageParcel& data, MessageParcel& reply)
{
    IAM_LOGD("UserAuthAsyncStub onIdentifyResultStub start");

    IdentifyResult identifyResult;
    int32_t result;

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(identifyResult.userId)) {
        IAM_LOGE("failed to read user id");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&identifyResult.token)) {
        IAM_LOGE("failed to read token");
        return E_READ_PARCEL_ERROR;
    }

    this->onIdentifyResult(result, identifyResult);
    if (!reply.WriteInt32(SUCCESS)) {
        IAM_LOGE("failed to write success");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserAuthAsyncStub::onExecutorPropertyInfoStub(MessageParcel& data, MessageParcel& reply)
{
    IAM_LOGD("UserAuthAsyncStub onExecutorPropertyInfoStub start");

    int32_t result;
    uint64_t authSubType;
    uint32_t remainTimes;
    uint32_t freezingTime;
    ExecutorProperty executorProperty = {};

    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint64(authSubType)) {
        IAM_LOGE("failed to read authSubType");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(remainTimes)) {
        IAM_LOGE("failed to read remainTimes");
        return E_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(freezingTime)) {
        IAM_LOGE("failed to read freezingTime");
        return E_READ_PARCEL_ERROR;
    }
    executorProperty.authSubType = static_cast<AuthSubType>(authSubType);
    executorProperty.freezingTime = freezingTime;
    executorProperty.remainTimes = remainTimes;
    executorProperty.result = static_cast<AuthSubType>(result);

    this->onExecutorPropertyInfo(executorProperty);
    if (!reply.WriteInt32(SUCCESS)) {
        IAM_LOGE("failed to write success");
        return E_WRITE_PARCEL_ERROR;
    }

    return SUCCESS;
}

int32_t UserAuthAsyncStub::onSetExecutorPropertyStub(MessageParcel& data, MessageParcel& reply)
{
    IAM_LOGD("UserAuthAsyncStub onSetExecutorPropertyStub start");
    int32_t result;
    if (!data.ReadInt32(result)) {
        IAM_LOGE("failed to read result");
        return E_READ_PARCEL_ERROR;
    }
    this->onSetExecutorProperty(result);
    if (!reply.WriteInt32(SUCCESS)) {
        IAM_LOGE("userauth failed to write success");
        return E_WRITE_PARCEL_ERROR;
    }
    return SUCCESS;
}

void UserAuthAsyncStub::onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo)
{
    IAM_LOGD("UserAuthAsyncStub onAcquireInfo start");

    if (authCallback_ == nullptr) {
        IAM_LOGE("userauthAsyncStub onAcquireInfo callback is nullptr");
        return;
    }

    IAM_LOGD("userauthAsyncStub module:%{public}d, acquireInfo:%{public}u",
        module, acquireInfo);

    authCallback_->onAcquireInfo(module, acquireInfo, extraInfo);
}

void UserAuthAsyncStub::onAuthResult(const int32_t result, const AuthResult &extraInfo)
{
    IAM_LOGD("UserAuthAsyncStub onAuthResult start");

    if (authCallback_ == nullptr) {
        IAM_LOGE("userauthAsyncStub onAuthResult callback is nullptr");
        return;
    }

    iamHitraceHelper_= nullptr;

    IAM_LOGD("userauthAsyncStub result:%{public}d, remain:%{public}u, freeze:%{public}u",
        result, extraInfo.remainTimes, extraInfo.freezingTime);
    authCallback_->onResult(result, extraInfo);
}

void UserAuthAsyncStub::onIdentifyResult(const int32_t result, const IdentifyResult &extraInfo)
{
    IAM_LOGD("UserAuthAsyncStub onIdentifyResult start");

    if (identifyCallback_ == nullptr) {
        IAM_LOGE("UserAuthAsyncStub onIdentifyResult callback is nullptr");
        return;
    }

    iamHitraceHelper_= nullptr;

    IAM_LOGD("UserAuthAsyncStub identify result:%{public}d, user id:%{public}d",
        result, extraInfo.userId);
    identifyCallback_->onResult(result, extraInfo);
}

void UserAuthAsyncStub::onExecutorPropertyInfo(const ExecutorProperty &result)
{
    IAM_LOGD("UserAuthAsyncStub onExecutorPropertyInfo start");

    if (getPropCallback_ == nullptr) {
        IAM_LOGE("UserAuthAsyncStub onExecutorPropertyInfo callback is nullptr");
        return;
    }

   IAM_LOGD("userauthAsyncStub result:%{public}d, sub:%{public}" PRIu64 ", remain:%{public}u, freeze:%{public}u",
        result.result, result.authSubType, result.remainTimes, result.freezingTime);
    getPropCallback_->onGetProperty(result);
}

void UserAuthAsyncStub::onSetExecutorProperty(const int32_t result)
{
    IAM_LOGD("UserAuthAsyncStub onSetExecutorProperty start");

    if (setPropCallback_ == nullptr) {
        IAM_LOGE("UserAuthAsyncStub onSetExecutorProperty callback is nullptr");
        return;
    }
    IAM_LOGD("userauthAsyncStub result:%{public}d", result);
    setPropCallback_->onSetProperty(result);
}
}  // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS
