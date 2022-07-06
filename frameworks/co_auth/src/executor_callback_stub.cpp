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
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "message_parcel.h"

#define LOG_LABEL Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
const std::string PERMISSION_AUTH_RESPOOL = "ohos.permission.ACCESS_AUTH_RESPOOL";
const std::string PERMISSION_ACCESS_COAUTH = "ohos.permission.ACCESS_COAUTH";

ExecutorCallbackStub::ExecutorCallbackStub(const std::shared_ptr<ExecutorCallback>& impl)
{
    callback_ = impl;
}

int32_t ExecutorCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    IAM_LOGD("ExecutorCallbackStub::OnRemoteRequest!");
    std::u16string descripter = ExecutorCallbackStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        IAM_LOGE("descriptor is not matched");
        return FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IExecutorCallback::ON_MESSENGER_READY):
            return OnMessengerReadyStub(data, reply);
        case static_cast<int32_t>(IExecutorCallback::ON_BEGIN_EXECUTE):
            return OnBeginExecuteStub(data, reply);
        case static_cast<int32_t>(IExecutorCallback::ON_END_EXECUTE):
            return OnEndExecuteStub(data, reply);
        case static_cast<int32_t>(IExecutorCallback::ON_SET_PROPERTY):
            return OnSetPropertyStub(data, reply);
        case static_cast<int32_t>(IExecutorCallback::ON_GET_PROPERTY):
            return OnGetPropertyStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t ExecutorCallbackStub::OnMessengerReadyStub(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGD("ExecutorCallbackStub::OnMessengerReadyStub");
    sptr<IExecutorMessenger> messenger = new (std::nothrow) ExecutorMessengerProxy(data.ReadRemoteObject());
    if (messenger == nullptr) {
        IAM_LOGE("messenger is nullptr");
        return FAIL;
    }
    std::vector<uint8_t> publicKey;
    data.ReadUInt8Vector(&publicKey);
    std::vector<uint64_t> templateIds;
    data.ReadUInt64Vector(&templateIds);
    OnMessengerReady(messenger, publicKey, templateIds);
    IAM_LOGD("OnMessengerReady GetRefPtr");
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnBeginExecuteStub(MessageParcel &data, MessageParcel &reply)
{
    uint64_t scheduleId = data.ReadUint64();
    std::vector<uint8_t> publicKey, buffer;
    data.ReadUInt8Vector(&publicKey);
    data.ReadUInt8Vector(&buffer);
    auto commandAttrs = Common::MakeShared<UserIam::UserAuth::Attributes>(buffer);
    IF_FALSE_LOGE_AND_RETURN_VAL(commandAttrs != nullptr, FAIL);
    int32_t ret = OnBeginExecute(scheduleId, publicKey, commandAttrs);
    if (!reply.WriteInt32(ret)) {
        IAM_LOGE("write ret failed");
        return FAIL;
    }
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnEndExecuteStub(MessageParcel &data, MessageParcel &reply)
{
    uint64_t scheduleId = data.ReadUint64();
    std::vector<uint8_t> buffer;
    data.ReadUInt8Vector(&buffer);
    auto consumerAttr = Common::MakeShared<UserIam::UserAuth::Attributes>(buffer);
    IF_FALSE_LOGE_AND_RETURN_VAL(consumerAttr != nullptr, FAIL);
    int32_t ret = OnEndExecute(scheduleId, consumerAttr);
    if (!reply.WriteInt32(ret)) {
        IAM_LOGE("write ret failed");
        return FAIL;
    }
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnGetPropertyStub(MessageParcel &data, MessageParcel &reply)
{
    std::vector<uint8_t> buffer;
    data.ReadUInt8Vector(&buffer);
    auto conditions = Common::MakeShared<UserIam::UserAuth::Attributes>(buffer);
    IF_FALSE_LOGE_AND_RETURN_VAL(conditions != nullptr, FAIL);
    auto values = Common::MakeShared<UserIam::UserAuth::Attributes>();
    IF_FALSE_LOGE_AND_RETURN_VAL(values != nullptr, FAIL);
    int32_t ret = OnGetProperty(conditions, values);
    if (!reply.WriteInt32(ret)) {
        IAM_LOGE("write ret failed");
        return FAIL;
    }

    std::vector<uint8_t> replyBuffer = values->Serialize();
    if (!reply.WriteUInt8Vector(replyBuffer)) {
        IAM_LOGE("write replyBuffer failed");
        return FAIL;
    }
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnSetPropertyStub(MessageParcel &data, MessageParcel &reply)
{
    std::vector<uint8_t> buffer;
    data.ReadUInt8Vector(&buffer);
    auto properties = Common::MakeShared<UserIam::UserAuth::Attributes>(buffer);
    IF_FALSE_LOGE_AND_RETURN_VAL(properties != nullptr, FAIL);
    int32_t ret = OnSetProperty(properties);
    if (!reply.WriteInt32(ret)) {
        IAM_LOGE("write ret failed");
        return FAIL;
    }
    return SUCCESS;
}

void ExecutorCallbackStub::OnMessengerReady(const sptr<IExecutorMessenger> &messenger, std::vector<uint8_t> &publicKey,
    std::vector<uint64_t> &templateIds)
{
    if (callback_ == nullptr) {
        return;
    }
    callback_->OnMessengerReady(messenger, publicKey, templateIds);
}

int32_t ExecutorCallbackStub::OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
    std::shared_ptr<UserIam::UserAuth::Attributes> commandAttrs)
{
    int32_t ret = FAIL;
    if (callback_ == nullptr) {
        return FAIL;
    } else {
        ret = callback_->OnBeginExecute(scheduleId, publicKey, commandAttrs);
    }
    return ret;
}

int32_t ExecutorCallbackStub::OnEndExecute(uint64_t scheduleId,
    std::shared_ptr<UserIam::UserAuth::Attributes> consumerAttr)
{
    int32_t ret = FAIL;
    if (callback_ == nullptr) {
        return FAIL;
    } else {
        ret = callback_->OnEndExecute(scheduleId, consumerAttr);
    }
    return ret;
}

int32_t ExecutorCallbackStub::OnSetProperty(std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    int32_t ret = FAIL;
    if (callback_ == nullptr) {
        return FAIL;
    } else {
        ret = callback_->OnSetProperty(properties);
    }
    return ret;
}

int32_t ExecutorCallbackStub::OnGetProperty(std::shared_ptr<UserIam::UserAuth::Attributes> conditions,
    std::shared_ptr<UserIam::UserAuth::Attributes> values)
{
    int32_t ret = FAIL;
    if (callback_ == nullptr) {
        return FAIL;
    } else {
        ret = callback_->OnGetProperty(conditions, values);
    }
    return ret;
}
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS