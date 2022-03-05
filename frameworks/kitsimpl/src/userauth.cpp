/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <new>

#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>

#include "system_ability_definition.h"
#include "user_auth.h"
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
UserAuth::UserAuth() = default;
UserAuth::~UserAuth() = default;

sptr<IUserAuth> UserAuth::GetProxy()
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth GetProxy is start");
    std::lock_guard lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth Failed to get system manager");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    if (obj == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth Failed to get userauth manager service");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new UserAuthDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<IUserAuth>(obj);
    deathRecipient_ = dr;
    USERAUTH_HILOGE(MODULE_INNERKIT, "userauth Succeed to connect userauth manager service");
    return proxy_;
}

void UserAuth::ResetProxy(const wptr<IRemoteObject> &remote)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth ResetProxy is start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        return;
    }

    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void UserAuth::UserAuthDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "OnRemoteDied is start");
    if (remote == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "OnRemoteDied failed, remote is nullptr");
        return;
    }

    UserAuth::GetInstance().ResetProxy(remote);
    USERAUTH_HILOGE(MODULE_INNERKIT, "userauth UserAuthDeathRecipient::Recv death notice.");
}

int32_t UserAuth::GetAvailableStatus(const AuthType authType, const AuthTurstLevel authTurstLevel)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth GetAvailableStatus is start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }

    int32_t ret = proxy_->GetAvailableStatus(authType, authTurstLevel);
    return ret;
}

void UserAuth::GetProperty(const GetPropertyRequest request, std::shared_ptr<GetPropCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth GetProperty is start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth GetProperty callback is Null");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ExecutorProperty result = {};
        result.result = E_RET_NOSERVER;
        callback->onGetProperty(result);
        return;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthAsyncStub failed, GetProperty IUserAuthCallback is nullptr");
        return;
    }
    proxy_->GetProperty(request, asyncStub);
}
void UserAuth::SetProperty(const SetPropertyRequest request, std::shared_ptr<SetPropCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth SetProperty is start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth SetProperty callback is Null");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        callback->onSetProperty(E_RET_NOSERVER);
        return;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthAsyncStub failed, SetProperty IUserAuthCallback is nullptr");
        return;
    }
    proxy_->SetProperty(request, asyncStub);
}
uint64_t UserAuth::Auth(const uint64_t challenge, const AuthType authType, const AuthTurstLevel authTurstLevel,
    std::shared_ptr<UserAuthCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth Auth is start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth Auth callback is Null");
        return INVALID_PARAMETERS;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthAsyncStub failed, Auth IUserAuthCallback is nullptr");
        return GENERAL_ERROR;
    }
    uint64_t ret = proxy_->Auth(challenge, authType, authTurstLevel, asyncStub);
    return ret;
}
uint64_t UserAuth::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
    const AuthTurstLevel authTurstLevel, std::shared_ptr<UserAuthCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth AuthUser is start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "userauth AuthUser callback is Null");
        return INVALID_PARAMETERS;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERKIT, "UserAuthAsyncStub failed, AuthUser IUserAuthCallback is nullptr");
        return GENERAL_ERROR;
    }
    uint64_t ret = proxy_->AuthUser(userId, challenge, authType, authTurstLevel, asyncStub);
    return ret;
}
int32_t UserAuth::CancelAuth(const uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth CancelAuth is start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }

    int32_t ret = proxy_->CancelAuth(contextId);
    return ret;
}
int32_t UserAuth::GetVersion()
{
    USERAUTH_HILOGD(MODULE_INNERKIT, "userauth GetVersion is start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return INVALID_PARAMETERS;
    }

    int32_t ret = proxy_->GetVersion();
    return ret;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
