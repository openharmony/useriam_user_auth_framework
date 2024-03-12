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

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_IDM_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
IdmCallbackService::IdmCallbackService(const std::shared_ptr<UserIdmClientCallback> &impl)
    : idmClientCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("IDM InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user idm service death, return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

IdmCallbackService::~IdmCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

void IdmCallbackService::OnResult(int32_t result, const Attributes &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", result);
    iamHitraceHelper_ = nullptr;
    if (idmClientCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return;
    }
    idmClientCallback_->OnResult(result, extraInfo);
}

void IdmCallbackService::OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo)
{
    IAM_LOGI("start, module:%{public}d acquireInfo:%{public}d", module, acquireInfo);
    if (idmClientCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return;
    }
    idmClientCallback_->OnAcquireInfo(module, static_cast<uint32_t>(acquireInfo), extraInfo);
}

IdmGetCredInfoCallbackService::IdmGetCredInfoCallbackService(
    const std::shared_ptr<GetCredentialInfoCallback> &impl) : getCredInfoCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user idm service death, return default cred info result to caller");
            std::vector<CredentialInfo> infoList;
            impl->OnCredentialInfo(infoList);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

IdmGetCredInfoCallbackService::~IdmGetCredInfoCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

void IdmGetCredInfoCallbackService::OnCredentialInfos(const std::vector<CredentialInfo> &credInfoList)
{
    IAM_LOGI("start, cred info vector size:%{public}zu", credInfoList.size());
    if (getCredInfoCallback_ == nullptr) {
        IAM_LOGE("getCredInfoCallback is nullptr");
        return;
    }

    getCredInfoCallback_->OnCredentialInfo(credInfoList);
}

IdmGetSecureUserInfoCallbackService::IdmGetSecureUserInfoCallbackService(
    const std::shared_ptr<GetSecUserInfoCallback> &impl) : getSecInfoCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user idm service death, return default secure info to caller");
            SecUserInfo info = {};
            impl->OnSecUserInfo(info);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

IdmGetSecureUserInfoCallbackService::~IdmGetSecureUserInfoCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

void IdmGetSecureUserInfoCallbackService::OnSecureUserInfo(const SecUserInfo &secUserInfo)
{
    IAM_LOGI("start, enrolled info vector size:%{public}zu", secUserInfo.enrolledInfo.size());
    if (getSecInfoCallback_ == nullptr) {
        IAM_LOGE("getSecInfoCallback_ is nullptr");
        return;
    }

    getSecInfoCallback_->OnSecUserInfo(secUserInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS