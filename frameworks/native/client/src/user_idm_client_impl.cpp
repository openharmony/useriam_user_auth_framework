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
#include "event_listener_callback_service.h"
#include "load_mode_client_util.h"
#include "iam_check.h"
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
    auto ret = proxy->OpenSession(userId, challenge);
    if (ret != SUCCESS) {
        IAM_LOGE("OpenSession ret = %{public}d", ret);
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

    auto ret = proxy->CloseSession(userId);
        if (ret != SUCCESS) {
        IAM_LOGE("CloseSession ret = %{public}d", ret);
    }
}

void UserIdmClientImpl::AddCredential(int32_t userId, const CredentialParameters &para,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d, authType:%{public}d, authSubType:%{public}d",
        userId, para.authType, para.pinType.value_or(PIN_SIX));
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

    sptr<IIamCallback> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    IpcCredentialPara credPara = {};
    credPara.authType = static_cast<int32_t>(para.authType);
    credPara.pinType = static_cast<int32_t>(para.pinType.value_or(PIN_SIX));
    credPara.token = std::move(para.token);
    auto ret = proxy->AddCredential(userId, credPara, wrapper, false);
    if (ret != SUCCESS) {
        IAM_LOGE("AddCredential fail, ret:%{public}d", ret);
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
}

void UserIdmClientImpl::UpdateCredential(int32_t userId, const CredentialParameters &para,
    const std::shared_ptr<UserIdmClientCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d, authType:%{public}d, authSubType:%{public}d",
        userId, para.authType, para.pinType.value_or(PIN_SIX));
    if (!callback) {
        IAM_LOGE("user idm client callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        Attributes extraInfo;
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            MANAGE_USER_IDM_PERMISSION
        }));
        callback->OnResult(result, extraInfo);
        return;
    }

    sptr<IIamCallback> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    IpcCredentialPara credPara = {};
    credPara.authType = static_cast<int32_t>(para.authType);
    credPara.pinType = static_cast<int32_t>(para.pinType.value_or(PIN_SIX));
    credPara.token = std::move(para.token);
    auto ret = proxy->UpdateCredential(userId, credPara, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("UpdateCredential fail, ret:%{public}d", ret);
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
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

    sptr<IIamCallback> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    auto ret = proxy->DelCredential(userId, credentialId, authToken, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("DelCredential fail, ret:%{public}d", ret);
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
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

    sptr<IIamCallback> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    auto ret = proxy->DelUser(userId, authToken, wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("DelUser fail, ret:%{public}d", ret);
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
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
    sptr<IIamCallback> wrapper(new (std::nothrow) IdmCallbackService(callback));
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
        std::vector<CredentialInfo> infoList;
        callback->OnCredentialInfo(GENERAL_ERROR, infoList);
        return GENERAL_ERROR;
    }

    sptr<IIdmGetCredInfoCallback> wrapper(new (std::nothrow) IdmGetCredInfoCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        std::vector<CredentialInfo> infoList;
        callback->OnCredentialInfo(GENERAL_ERROR, infoList);
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
        int32_t result = LoadModeUtil::GetProxyNullResultCode(__func__, std::vector<std::string>({
            USE_USER_IDM_PERMISSION
        }));
        SecUserInfo info = {};
        callback->OnSecUserInfo(result, info);
        return result;
    }

    sptr<IIdmGetSecureUserInfoCallback> wrapper(
        new (std::nothrow) IdmGetSecureUserInfoCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        SecUserInfo info = {};
        callback->OnSecUserInfo(GENERAL_ERROR, info);
        return GENERAL_ERROR;
    }
    return proxy->GetSecInfo(userId, wrapper);
}

sptr<IUserIdm> UserIdmClientImpl::GetProxy()
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

    proxy_ = iface_cast<IUserIdm>(obj);
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

    sptr<IIamCallback> wrapper(new (std::nothrow) IdmCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    auto ret = proxy->ClearRedundancyCredential(wrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("ClearRedundancyCredential fail, ret:%{public}d", ret);
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
}

int32_t UserIdmClientImpl::RegistCredChangeEventListener(const std::vector<AuthType> &authTypes,
    const std::shared_ptr<CredChangeEventListener> &listener)
{
    IAM_LOGI("start");

    auto proxy = GetProxy();
    IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);

    return EventListenerCallbackManager::GetInstance().AddCredChangeEventListener(proxy, authTypes, listener);
}

int32_t UserIdmClientImpl::UnRegistCredChangeEventListener(const std::shared_ptr<CredChangeEventListener> &listener)
{
    IAM_LOGI("start");

    auto proxy = GetProxy();
    IF_FALSE_LOGE_AND_RETURN_VAL(proxy != nullptr, GENERAL_ERROR);

    return EventListenerCallbackManager::GetInstance().RemoveCredChangeEventListener(proxy, listener);
}

int32_t UserIdmClientImpl::GetCredentialInfoSync(int32_t userId, AuthType authType,
    std::vector<CredentialInfo> &credentialInfoList)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d", userId, authType);
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    std::vector<IpcCredentialInfo> ipcCredInfoList;
    auto ret = proxy->GetCredentialInfoSync(userId, authType, ipcCredInfoList);
    if (ret != SUCCESS) {
        IAM_LOGE("GetCredentialInfoSync fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }

    for (auto &iter : ipcCredInfoList) {
        CredentialInfo credentialInfo;
        credentialInfo.authType = static_cast<AuthType>(iter.authType);
        credentialInfo.pinType = static_cast<PinSubType>(iter.pinType);
        credentialInfo.credentialId = iter.credentialId;
        credentialInfo.templateId = iter.credentialId;
        credentialInfoList.push_back(credentialInfo);
    }

    IAM_LOGI("GetCredentialInfoSync success, credential num:%{public}zu", credentialInfoList.size());
    return SUCCESS;
}

void UserIdmClientImpl::UserIdmImplDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    CallbackManager::GetInstance().OnServiceDeath();
    EventListenerCallbackManager::GetInstance().OnServiceDeath();
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