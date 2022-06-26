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

#include "executor_callback_proxy.h"

#include "iam_logger.h"
#include "message_parcel.h"

#define LOG_LABEL Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
void ExecutorCallbackProxy::OnMessengerReady(const sptr<IExecutorMessenger> &messenger,
    std::vector<uint8_t> &frameworkPublicKey, std::vector<uint64_t> &templateIds)
{
    IAM_LOGD("ExecutorCallbackProxy OnMessengerReady");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return;
    }

    if (messenger.GetRefPtr() == nullptr) {
        IAM_LOGE("messenger.GetRefPtr() is nullptr");
        return;
    }
    if (!data.WriteRemoteObject(messenger.GetRefPtr()->AsObject())) {
        IAM_LOGE("write RemoteObject failed");
        return;
    }
    if (!data.WriteUInt8Vector(frameworkPublicKey)) {
        IAM_LOGE("write frameworkPublicKey failed");
        return;
    }
    if (!data.WriteUInt64Vector(templateIds)) {
        IAM_LOGE("write templateIds failed");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_MESSENGER_READY), data, reply);
    IAM_LOGD(ret);
}

int32_t ExecutorCallbackProxy::OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
    std::shared_ptr<UserIam::UserAuth::Attributes> commandAttrs)
{
    if (commandAttrs == nullptr) {
        IAM_LOGE("commandAttrs is nullptr");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }

    if (!data.WriteUint64(scheduleId)) {
        IAM_LOGE("write scheduleId failed");
        return FAIL;
    }
    if (!data.WriteUInt8Vector(publicKey)) {
        IAM_LOGE("write publicKey failed");
        return FAIL;
    }
    std::vector<uint8_t> buffer = commandAttrs.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("write buffer failed");
        return FAIL;
    }

    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_BEGIN_EXECUTE), data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("read result failed");
        return FAIL;
    }
    IAM_LOGI("result = %{public}d", result);
    return result;
}

int32_t ExecutorCallbackProxy::OnEndExecute(uint64_t scheduleId,
    std::shared_ptr<UserIam::UserAuth::Attributes> consumerAttr)
{
    if (consumerAttr == nullptr) {
        IAM_LOGE("consumerAttr is null");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }

    if (!data.WriteUint64(scheduleId)) {
        IAM_LOGE("write scheduleId failed");
        return FAIL;
    }

    std::vector<uint8_t> buffer  = consumerAttr.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("write buffer failed");
        return FAIL;
    }

    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_END_EXECUTE), data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("read result failed");
        return FAIL;
    }
    IAM_LOGI("result = %{public}d", result);
    return result;
}

int32_t ExecutorCallbackProxy::OnSetProperty(std::shared_ptr<UserIam::UserAuth::Attributes> properties)
{
    if (properties == nullptr) {
        IAM_LOGE("properties is null");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }
    std::vector<uint8_t> buffer  =  properties.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("write buffer failed");
        return FAIL;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_SET_PROPERTY), data, reply);
    if (!ret) {
        IAM_LOGE("send request failed");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("read result failed");
        return FAIL;
    }
    IAM_LOGI("result = %{public}d", result);
    return result;
}

int32_t ExecutorCallbackProxy::OnGetProperty(std::shared_ptr<UserIam::UserAuth::Attributes> conditions,
    std::shared_ptr<UserIam::UserAuth::Attributes> values)
{
    if (conditions == nullptr || values == nullptr) {
        IAM_LOGE("param is null");
        return INVALID_PARAMETERS;
    }
    MessageParcel data;
    MessageParcel reply;
    if (values == nullptr) {
        IAM_LOGE("values is null.");
        return FAIL;
    }

    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        IAM_LOGE("write descriptor failed");
        return FAIL;
    }

    std::vector<uint8_t> buffer =  conditions.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        IAM_LOGE("write buffer failed");
        return FAIL;
    }

    std::vector<uint8_t> valuesReply;
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_GET_PROPERTY), data, reply); // must sync
    if (!ret) {
        IAM_LOGE("send request failed");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        IAM_LOGE("read result failed");
        return FAIL;
    }
    if (!reply.ReadUInt8Vector(&valuesReply)) {
        IAM_LOGE("read valuesReply failed");
        return FAIL;
    } else {
        values->Unpack(valuesReply);
    }
    IAM_LOGI("result = %{public}d", result);
    return result;
}


bool ExecutorCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        IAM_LOGE("get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        IAM_LOGE("send request failed, result = %{public}d", result);
        return false;
    }
    return true;
}
}
}
}