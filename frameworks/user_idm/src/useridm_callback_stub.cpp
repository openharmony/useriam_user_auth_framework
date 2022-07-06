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

#include "useridm_callback_stub.h"

#include <message_parcel.h>

#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
namespace UserAuthDomain = OHOS::UserIAM::UserAuth;

UserIDMCallbackStub::UserIDMCallbackStub(const std::shared_ptr<IDMCallback> &impl)
    : callback_(impl),
      idmCallback_(nullptr),
      iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("IDM InnerKit"))
{
}

UserIDMCallbackStub::UserIDMCallbackStub(const std::shared_ptr<UserAuthDomain::IdmCallback> &impl)
    : callback_(nullptr),
      idmCallback_(impl),
      iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("IDM InnerKit"))
{
}

int32_t UserIDMCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    IAM_LOGD("UserIDMCallbackStub::OnRemoteRequest, cmd = %u, flags= %d", code,
        option.GetFlags());
    
    if (UserIDMCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("UserIDMCallbackStub::OnRemoteRequest failed, descriptor is not matched!");
        return FAIL;
    }
    
    switch (code) {
        case static_cast<int32_t>(IIDMCallback::IDM_CALLBACK_ON_RESULT):
            return OnResultStub(data, reply);
        case static_cast<int32_t>(IIDMCallback::IDM_CALLBACK_ON_ACQUIRE_INFO):
            return OnAcquireInfoStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserIDMCallbackStub::OnResultStub(MessageParcel& data, MessageParcel& reply)
{
    IAM_LOGI("UserIDMCallbackStub OnResultStub start");
    RequestResult reqRet;
    int32_t result = data.ReadInt32();
    reqRet.credentialId = data.ReadUint64();
    this->OnResult(result, reqRet);
    return SUCCESS;
}

int32_t UserIDMCallbackStub::OnAcquireInfoStub(MessageParcel& data, MessageParcel& reply)
{
    IAM_LOGI("UserIDMCallbackStub OnAcquireInfoStub start");
    int32_t ret = SUCCESS;
    RequestResult reqRet;
    int32_t module = data.ReadInt32();
    int32_t acquire = data.ReadInt32();
    reqRet.credentialId = data.ReadUint64();
    OnAcquireInfo(module, acquire, reqRet);
    if (!reply.WriteInt32(ret)) {
        IAM_LOGE("failed to WriteInt32(ret)");
        ret = FAIL;
    }
    return ret;
}

void UserIDMCallbackStub::OnResult(int32_t result, RequestResult reqRet)
{
    IAM_LOGD("UserIDMCallbackStub OnResult start");
    iamHitraceHelper_ = nullptr;
    if (callback_ != nullptr) {
        callback_->OnResult(result, reqRet);
        return;
    }
    if (idmCallback_ != nullptr) {
        UserAuthDomain::RequestResult para = {};
        para.credentialId = reqRet.credentialId;
        idmCallback_->OnResult(result, para);
        return;
    }
    IAM_LOGE("callback_ is nullptr and idmCallback_ is nullptr");
}

void UserIDMCallbackStub::OnAcquireInfo(int32_t module, int32_t acquire, RequestResult reqRet)
{
    IAM_LOGD("UserIDMCallbackStub OnAcquireInfo start");
    if (callback_ != nullptr) {
        callback_->OnAcquireInfo(module, acquire, reqRet);
        return;
    }
    if (idmCallback_ != nullptr) {
        UserAuthDomain::RequestResult para = {};
        para.credentialId = reqRet.credentialId;
        idmCallback_->OnAcquireInfo(module, acquire, para);
        return;
    }
    IAM_LOGE("callback_ is nullptr and idmCallback_ is nullptr");
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
