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

#include "user_auth_native.h"

#include <cinttypes>
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <sstream>
#include <system_ability_definition.h>

#include "iam_check.h"
#include "iam_logger.h"
#include "system_ability_definition.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<IUserAuth> UserAuthNative::GetProxy()
{
    IAM_LOGD("GetProxy start");
    std::lock_guard lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("Failed to get system manager");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    if (obj == nullptr) {
        IAM_LOGE("Failed to get userauth service");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new (std::nothrow) UserAuthDeathRecipient();
    IF_FALSE_LOGE_AND_RETURN_VAL(dr != nullptr, nullptr);
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        IAM_LOGE("Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<IUserAuth>(obj);
    deathRecipient_ = dr;
    IAM_LOGI("Succeed to connect userauth service");
    return proxy_;
}

void UserAuthNative::ResetProxy(const wptr<IRemoteObject> &remote)
{
    IAM_LOGD("ResetProxy start");
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

void UserAuthNative::UserAuthDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGD("OnRemoteDied start");
    if (remote == nullptr) {
        IAM_LOGE("OnRemoteDied failed, remote is nullptr");
        return;
    }

    UserAuthNative::GetInstance().ResetProxy(remote);
}

int32_t UserAuthNative::GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel)
{
    IAM_LOGD("GetAvailableStatus start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }

    return proxy->GetAvailableStatus(authType, authTrustLevel);
}

void UserAuthNative::GetProperty(const GetPropertyRequest &request, std::shared_ptr<GetPropCallback> callback)
{
    IAM_LOGD("GetProperty start");
    if (callback == nullptr) {
        IAM_LOGE("GetProperty callback is nullptr");
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
        IAM_LOGE("GetProperty asyncStub is nullptr");
        return;
    }
    proxy->GetProperty(request, asyncStub);
}

void UserAuthNative::GetProperty(const int32_t userId, const GetPropertyRequest &request,
    std::shared_ptr<GetPropCallback> callback)
{
    IAM_LOGD("GetProperty start");
    if (callback == nullptr) {
        IAM_LOGE("GetProperty callback is nullptr");
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
        IAM_LOGE("GetProperty asyncStub is nullptr");
        return;
    }
    proxy->GetProperty(userId, request, asyncStub);
}

void UserAuthNative::SetProperty(const SetPropertyRequest &request, std::shared_ptr<SetPropCallback> callback)
{
    IAM_LOGD("SetProperty start");
    if (callback == nullptr) {
        IAM_LOGE("SetProperty callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        callback->onSetProperty(E_RET_NOSERVER);
        return;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        IAM_LOGE("SetProperty asyncStub is nullptr");
        return;
    }

    proxy->SetProperty(request, asyncStub);
    IAM_LOGD("SetProperty end");
}

uint64_t UserAuthNative::Auth(const uint64_t challenge, const AuthType authType, const AuthTrustLevel authTrustLevel,
    std::shared_ptr<UserAuthCallback> callback)
{
    IAM_LOGD("Auth start");
    if (callback == nullptr) {
        IAM_LOGE("Auth callback is nullptr");
        return INVALID_PARAMETERS;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        IAM_LOGE("Auth asyncStub is nullptr");
        return GENERAL_ERROR;
    }
    return proxy->Auth(challenge, authType, authTrustLevel, asyncStub);
}

uint64_t UserAuthNative::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, std::shared_ptr<UserAuthCallback> callback)
{
    IAM_LOGD("AuthUser start");
    if (callback == nullptr) {
        IAM_LOGE("AuthUser callback is nullptr");
        return INVALID_PARAMETERS;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        IAM_LOGE("AuthUser asyncStub is nullptr");
        return GENERAL_ERROR;
    }
    return proxy->AuthUser(userId, challenge, authType, authTrustLevel, asyncStub);
}

int32_t UserAuthNative::CancelAuth(const uint64_t contextId)
{
    IAM_LOGD("CancelAuth start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }

    return proxy->CancelAuth(contextId);
}

uint64_t UserAuthNative::Identify(const uint64_t challenge, const AuthType authType,
    std::shared_ptr<UserIdentifyCallback> callback)
{
    IAM_LOGD("Identify start");
    if (callback == nullptr) {
        IAM_LOGE("Identify callback is nullptr");
        return INVALID_PARAMETERS;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }
    sptr<IUserAuthCallback> asyncStub = new (std::nothrow) UserAuthAsyncStub(callback);
    if (asyncStub == nullptr) {
        IAM_LOGE("Identify asyncStub is nullptr");
        return GENERAL_ERROR;
    }
    return proxy->Identify(challenge, authType, asyncStub);
}

int32_t UserAuthNative::CancelIdentify(const uint64_t contextId)
{
    IAM_LOGD("CancelIdentify start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_RET_NOSERVER;
    }

    return proxy->CancelIdentify(contextId);
}

int32_t UserAuthNative::GetVersion()
{
    IAM_LOGD("GetVersion start");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return INVALID_PARAMETERS;
    }

    return proxy->GetVersion();
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
