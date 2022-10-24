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

#include "user_idm_callback_service.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
IdmCallbackService::IdmCallbackService(const std::shared_ptr<UserIdmClientCallback> &impl)
    : idmClientCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("IDM InnerKit"))
{
}

void IdmCallbackService::OnResult(int32_t result, const Attributes &extraInfo)
{
    iamHitraceHelper_ = nullptr;
    if (idmClientCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return;
    }
    idmClientCallback_->OnResult(result, extraInfo);
}

void IdmCallbackService::OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo)
{
    if (idmClientCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return;
    }
    idmClientCallback_->OnAcquireInfo(module, static_cast<uint32_t>(acquireInfo), extraInfo);
}

IdmGetCredInfoCallbackService::IdmGetCredInfoCallbackService(
    const std::shared_ptr<GetCredentialInfoCallback> &impl) : getCredInfoCallback_(impl)
{
}

void IdmGetCredInfoCallbackService::OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
    const std::optional<PinSubType> pinSubType)
{
    if (getCredInfoCallback_ == nullptr) {
        IAM_LOGE("getCredInfoCallback is nullptr");
        return;
    }
    
    std::vector<UserAuth::CredentialInfo> credInfoList;
    for (const auto &it : infoList) {
        if (it == nullptr) {
            continue;
        }
        UserAuth::CredentialInfo info = {};
        info.credentialId = it->GetCredentialId();
        info.templateId = it->GetTemplateId();
        info.authType = it->GetAuthType();
        if (info.authType == PIN && pinSubType.has_value()) {
            info.pinType = pinSubType;
        }
        credInfoList.push_back(info);
    }
    getCredInfoCallback_->OnCredentialInfo(credInfoList);
}

IdmGetSecureUserInfoCallbackService::IdmGetSecureUserInfoCallbackService(
    const std::shared_ptr<GetSecUserInfoCallback> &impl) : getSecInfoCallback_(impl)
{
}

void IdmGetSecureUserInfoCallbackService::OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info)
{
    if (info == nullptr) {
        IAM_LOGE("secure user info is nullptr");
        return;
    }
    SecUserInfo secUserInfo = {};
    secUserInfo.secureUid = info->GetSecUserId();
    getSecInfoCallback_->OnSecUserInfo(secUserInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS