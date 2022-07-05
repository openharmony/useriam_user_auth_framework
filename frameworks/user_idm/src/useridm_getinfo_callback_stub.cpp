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

#include "useridm_getinfo_callback_stub.h"

#include <message_parcel.h>

#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t UserIDMGetInfoCallbackStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IAM_LOGI("UserIDMGetInfoCallbackStub::OnRemoteRequest, cmd = %{public}u, flags= %d",
        code, option.GetFlags());

    if (UserIDMGetInfoCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        IAM_LOGE("UserIDMGetInfoCallbackStub::OnRemoteRequest failed, descriptor is not matched!");
        return FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IGetInfoCallback::ON_GET_INFO):
            return OnGetInfoStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t UserIDMGetInfoCallbackStub::OnGetInfoStub(MessageParcel& data, MessageParcel& reply)
{
    IAM_LOGI("UserIDMGetInfoCallbackStub OnGetInfoStub start");
    uint32_t vectorSize = 0;
    std::vector<CredentialInfo> credInfos;
    if (!data.ReadUint32(vectorSize)) {
        IAM_LOGE("read size fail");
        OnGetInfo(credInfos);
        return FAIL;
    }
    for (uint32_t i = 0; i < vectorSize; i++) {
        CredentialInfo info;
        if (!data.ReadUint64(info.credentialId)) {
            IAM_LOGE("read credential id fail");
            OnGetInfo(credInfos);
            return FAIL;
        }
        uint32_t authType = 0;
        if (!data.ReadUint32(authType)) {
            IAM_LOGE("read type fail");
            OnGetInfo(credInfos);
            return FAIL;
        }
        info.authType = static_cast<AuthType>(authType);
        uint64_t authSubType = 0;
        if (!data.ReadUint64(authSubType)) {
            IAM_LOGE("read subtype fail");
            OnGetInfo(credInfos);
            return FAIL;
        }
        info.authSubType = static_cast<AuthSubType>(authSubType);
        if (!data.ReadUint64(info.templateId)) {
            IAM_LOGE("read template id fail");
            OnGetInfo(credInfos);
            return FAIL;
        }
        credInfos.push_back(info);
    }
    OnGetInfo(credInfos);
    if (!reply.WriteInt32(SUCCESS)) {
        IAM_LOGE("write result fail");
        return FAIL;
    }
    return SUCCESS;
}

void UserIDMGetInfoCallbackStub::OnGetInfo(std::vector<CredentialInfo>& infos)
{
    IAM_LOGI("UserIDMGetInfoCallbackStub OnGetInfo start");
    if (infos.size() > 0) {
        IAM_LOGI("have data");
    } else {
        IAM_LOGI("get no data");
    }
    
    if (callback_ != nullptr) {
        callback_->OnGetInfo(infos);
        return;
    }
    if (idmCallback_ != nullptr) {
        std::vector<CredentialInfo> credInfos;
        for (auto &credInfo : infos) {
            CredentialInfo credential = {};
            credential.authType = static_cast<AuthType>(credInfo.authType);
            credential.authSubType = static_cast<AuthSubType>(credInfo.authSubType);
            credential.credentialId = credInfo.credentialId;
            credential.templateId = credInfo.templateId;
            credInfos.push_back(credential);
        }
        idmCallback_->OnGetInfo(credInfos);
        return;
    }
    IAM_LOGE("callback_ is nullptr and idmCallback_ is nullptr");
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
