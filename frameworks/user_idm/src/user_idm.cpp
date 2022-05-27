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

#include "user_idm.h"
#include "iuser_idm.h"
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>
#include "useridm_callback_stub.h"
#include "useridm_getinfo_callback_stub.h"
#include "useridm_getsecinfo_callback_stub.h"
#include "useridm_info.h"
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
namespace UserIdmDomain = OHOS::UserIAM::UserIDM;

sptr<UserIdmDomain::IUserIDM> UserIdm::GetIdmProxy()
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "GetIdmProxy start");

    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sam) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "failed to get systemAbilityManager");
        return nullptr;
    }

    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERIDM);
    if (!obj) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "failed to get remoteObject");
        return nullptr;
    }

    sptr<IRemoteObject::DeathRecipient> dr = new IdmDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<UserIdmDomain::IUserIDM>(obj);
    deathRecipient_ = dr;

    USERAUTH_HILOGD(MODULE_INNERAPI, "Succeed to connect manager service");
    return proxy_;
}

void UserIdm::ResetIdmProxy(const wptr<IRemoteObject>& remote)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "ResetIdmProxy start");

    std::lock_guard<std::mutex> lock(mutex_);
    if (!proxy_) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "ResetIdmProxy proxy is nullptr");
        return;
    }

    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void UserIdm::IdmDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "OnRemoteDied start");

    if (remote == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "OnRemoteDied failed, remote is nullptr");
        return;
    }

    UserIdm::GetInstance().ResetIdmProxy(remote);
    USERAUTH_HILOGD(MODULE_INNERAPI, "UserIDMDeathRecipient::Recv death notice");
}

uint64_t UserIdm::OpenSession(const int32_t userId)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "OpenSession start with userid: %{public}d", userId);

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "OpenSession proxy is nullptr");
        return FAIL;
    }
    return proxy->OpenSession(userId);
}

void UserIdm::CloseSession(const int32_t userId)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "CloseSession start with userid: %{public}d", userId);

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "CloseSession proxy is nullptr");
        return;
    }

    proxy->CloseSession(userId);
}

void UserIdm::AddCredential(const int32_t userId, const AddCredInfo& credInfo,
    const std::shared_ptr<IdmCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "AddCredential start with userid: %{public}d", userId);

    if (callback == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "AddCredential callback is nullptr");
        return;
    }

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "AddCredential proxy is nullptr");
        return;
    }

    UserIdmDomain::AddCredInfo info = {};
    info.authType = static_cast<UserIdmDomain::AuthType>(credInfo.authType);
    info.authSubType = static_cast<UserIdmDomain::AuthSubType>(credInfo.authSubType);
    info.token = credInfo.token;
    sptr<UserIdmDomain::IIDMCallback> callbackStub = new UserIdmDomain::UserIDMCallbackStub(callback);
    proxy->AddCredential(userId, info, callbackStub);
}

void UserIdm::UpdateCredential(const int32_t userId, const AddCredInfo& credInfo,
    const std::shared_ptr<IdmCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "UpdateCredential start with userid: %{public}d", userId);

    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERAPI, "UpdateCredential callback is nullptr");
        return;
    }
    
    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERAPI, "UpdateCredential proxy is nullptr");
        return;
    }

    UserIdmDomain::AddCredInfo info = {};
    info.authType = static_cast<UserIdmDomain::AuthType>(credInfo.authType);
    info.authSubType = static_cast<UserIdmDomain::AuthSubType>(credInfo.authSubType);
    info.token = credInfo.token;
    sptr<UserIdmDomain::IIDMCallback> callbackStub = new UserIdmDomain::UserIDMCallbackStub(callback);
    proxy->UpdateCredential(userId, info, callbackStub);
}

int32_t UserIdm::Cancel(const int32_t userId)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "Cancel start with userid: %{public}d", userId);

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "Cancel proxy is nullptr");
        return FAIL;
    }

    return proxy->Cancel(userId);
}


void UserIdm::DelUser(const int32_t userId, const std::vector<uint8_t> authToken,
    const std::shared_ptr<IdmCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "DelUser start with userid: %{public}d", userId);

    if (callback == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "DelUser callback is nullptr");
        return;
    }

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "DelUser proxy is nullptr");
        return;
    }

    sptr<UserIdmDomain::IIDMCallback> callbackStub = new UserIdmDomain::UserIDMCallbackStub(callback);
    proxy->DelUser(userId, authToken, callbackStub);
}

void UserIdm::DelCredential(const int32_t userId, const uint64_t credentialId,
    const std::vector<uint8_t> authToken, const std::shared_ptr<IdmCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "DelCredential start with userid: %{public}d", userId);

    if (callback == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "DelCredential callback is nullptr");
        return;
    }

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "DelCredential proxy is nullptr");
        return;
    }

    sptr<UserIdmDomain::IIDMCallback> callbackStub = new UserIdmDomain::UserIDMCallbackStub(callback);
    proxy->DelCredential(userId, credentialId, authToken, callbackStub);
}

int32_t UserIdm::GetAuthInfo(int32_t userId, AuthType authType, const std::shared_ptr<GetInfoCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "GetAuthInfo start with userid: %{public}d", userId);

    if (callback == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "GetAuthInfo callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "GetAuthInfo proxy is nullptr");
        return FAIL;
    }

    UserIdmDomain::AuthType type = static_cast<UserIdmDomain::AuthType>(authType);
    sptr<UserIdmDomain::IGetInfoCallback> callbackStub = new UserIdmDomain::UserIDMGetInfoCallbackStub(callback);
    return proxy->GetAuthInfo(userId, type, callbackStub);
}

int32_t UserIdm::GetSecInfo(const int32_t userId, const std::shared_ptr<GetSecInfoCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "GetSecInfo start with userid: %{public}d", userId);

    if (callback == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "GetSecInfo callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "GetSecInfo proxy is nullptr");
        return FAIL;
    }

    sptr<UserIdmDomain::IGetSecInfoCallback> callbackStub = new UserIdmDomain::UserIDMGetSecInfoCallbackStub(callback);
    return proxy->GetSecInfo(userId, callbackStub);
}

int32_t UserIdm::EnforceDelUser(const int32_t userId, const std::shared_ptr<IdmCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "EnforceDelUser start with userid: %{public}d", userId);
    
    if (callback == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "EnforceDelUser callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetIdmProxy();
    if (proxy == nullptr) {
        USERAUTH_HILOGD(MODULE_INNERAPI, "EnforceDelUser proxy is nullptr");
        return FAIL;
    }

    sptr<UserIdmDomain::IIDMCallback> callbackStub = new UserIdmDomain::UserIDMCallbackStub(callback);
    return proxy->EnforceDelUser(userId, callbackStub);
}
} // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS