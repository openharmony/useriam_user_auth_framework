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

#include "user_idm_client_impl.h"

#include "system_ability_definition.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "ipc_client_utils.h"
#include "user_idm_callback_service.h"

#define LOG_TAG "USER_IDM_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::vector<uint8_t> UserIdmClientImpl::OpenSession(int32_t userId)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return {};
    }

    std::vector<uint8_t> challenge;
    auto success = proxy->OpenSession(userId, challenge);
    if (success != SUCCESS) {
        IAM_LOGE("OpenSession ret = %{public}d", success);
    }

    return challenge;
}

void UserIdmClientImpl::CloseSession(int32_t userId)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return;
    }

    proxy->CloseSession(userId);
}

void UserIdmClientImpl::AddCredential(int32_t userId, const CredentialParameters &para,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d", userId, para.authType);
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    UserIdmInterface::CredentialPara credPara = {};
    credPara.authType = para.authType;
    credPara.pinType = para.pinType.value_or(PIN_SIX);
    credPara.token = std::move(para.token);
    proxy->AddCredential(userId, credPara, wrapper, false);
}

void UserIdmClientImpl::UpdateCredential(int32_t userId, const CredentialParameters &para,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d", userId, para.authType);
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    UserIdmInterface::CredentialPara credPara = {};
    credPara.authType = para.authType;
    credPara.pinType = para.pinType.value_or(PIN_SIX);
    credPara.token = std::move(para.token);
    proxy->UpdateCredential(userId, credPara, wrapper);
}

int32_t UserIdmClientImpl::Cancel(int32_t userId)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->Cancel(userId);
}

void UserIdmClientImpl::DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    proxy->DelCredential(userId, credentialId, authToken, wrapper);
}

void UserIdmClientImpl::DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    proxy->DelUser(userId, authToken, wrapper);
}

int32_t UserIdmClientImpl::EraseUser(int32_t userId, const std::shared_ptr<UserIdmClientCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    sptr<IdmCallbackInterface> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    return proxy->EnforceDelUser(userId, wrapper);
}

int32_t UserIdmClientImpl::GetCredentialInfo(int32_t userId, AuthType authType,
    const std::shared_ptr<GetCredentialInfoCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d", userId, authType);
    if (!callback) {
        IAM_LOGE("get credential info callback is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        std::vector<CredentialInfo> infoList;
        callback->OnCredentialInfo(infoList);
        return GENERAL_ERROR;
    }

    sptr<IdmGetCredInfoCallbackInterface> wrapper(new (std::nothrow) IdmGetCredInfoCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        std::vector<CredentialInfo> infoList;
        callback->OnCredentialInfo(infoList);
        return GENERAL_ERROR;
    }
    return proxy->GetCredentialInfo(userId, authType, wrapper);
}

int32_t UserIdmClientImpl::GetSecUserInfo(int32_t userId, const std::shared_ptr<GetSecUserInfoCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d", userId);
    if (!callback) {
        IAM_LOGE("get secure info callback is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        SecUserInfo info = {};
        callback->OnSecUserInfo(info);
        return GENERAL_ERROR;
    }

    sptr<IdmGetSecureUserInfoCallbackInterface> wrapper(
        new (std::nothrow) IdmGetSecureUserInfoCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        SecUserInfo info = {};
        callback->OnSecUserInfo(info);
        return GENERAL_ERROR;
    }
    return proxy->GetSecInfo(userId, wrapper);
}

sptr<UserIdmInterface> UserIdmClientImpl::GetProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_USERIDM);
    if (obj == nullptr) {
        IAM_LOGE("remote object is null");
        return proxy_;
    }
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) UserIdmImplDeathRecipient());
    if ((dr == nullptr) || (obj->IsProxyObject() && !obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient fail");
        return proxy_;
    }

    proxy_ = iface_cast<UserIdmInterface>(obj);
    deathRecipient_ = dr;
    return proxy_;
}

void UserIdmClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        IAM_LOGE("proxy_ is null");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        IAM_LOGI("need reset");
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
    IAM_LOGI("end reset proxy");
}

void UserIdmClientImpl::ClearRedundancyCredential(const std::shared_ptr<UserIdmClientCallback> &callback)
{
    IAM_LOGI("start");
    if (!callback) {
        IAM_LOGE("ClearRedundancyCredential callback is nullptr");
        return;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    sptr<IdmCallbackInterface> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    proxy->ClearRedundancyCredential(wrapper);
}

void UserIdmClientImpl::UserIdmImplDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    CallbackManager::GetInstance().OnServiceDeath();
    UserIdmClientImpl::Instance().ResetProxy(remote);
}

UserIdmClientImpl &UserIdmClientImpl::Instance()
{
    static UserIdmClientImpl impl;
    return impl;
}

UserIdmClient &UserIdmClient::GetInstance()
{
    return UserIdmClientImpl::Instance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS