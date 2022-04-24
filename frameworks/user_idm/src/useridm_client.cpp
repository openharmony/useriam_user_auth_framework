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

#include "useridm_client.h"
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>
#include "useridm_callback_stub.h"
#include "useridm_getinfo_callback_stub.h"
#include "useridm_getsecinfo_callback_stub.h"
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
UserIDMClient::UserIDMClient() = default;
UserIDMClient::~UserIDMClient() = default;

sptr<IUserIDM> UserIDMClient::GetUserIDMProxy()
{
    USERIDM_HILOGD(MODULE_CLIENT, "GetUserIDMProxy start");

    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sam) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to get systemAbilityManager");
        return nullptr;
    }

    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERIDM);
    if (!obj) {
        USERIDM_HILOGE(MODULE_CLIENT, "failed to get remoteObject");
        return nullptr;
    }

    sptr<IRemoteObject::DeathRecipient> dr = new UserIDMDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        USERIDM_HILOGE(MODULE_CLIENT, "Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<IUserIDM>(obj);
    deathRecipient_ = dr;

    USERIDM_HILOGD(MODULE_CLIENT, "Succeed to connect manager service");
    return proxy_;
}

void UserIDMClient::ResetUserIDMProxy(const wptr<IRemoteObject>& remote)
{
    USERIDM_HILOGD(MODULE_CLIENT, "ResetUserIDMProxy start");

    std::lock_guard<std::mutex> lock(mutex_);
    if (!proxy_) {
        USERIDM_HILOGE(MODULE_CLIENT, "ResetUserIDMProxy proxy is nullptr");
        return;
    }

    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void UserIDMClient::UserIDMDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    USERIDM_HILOGD(MODULE_CLIENT, "OnRemoteDied start");

    if (remote == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "OnRemoteDied failed, remote is nullptr");
        return;
    }

    UserIDMClient::GetInstance().ResetUserIDMProxy(remote);
    USERIDM_HILOGE(MODULE_CLIENT, "UserIDMDeathRecipient::Recv death notice");
}

uint64_t UserIDMClient::OpenSession()
{
    USERIDM_HILOGD(MODULE_CLIENT, "OpenSession start");

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "OpenSession proxy is nullptr");
        return FAIL;
    }
    return proxy->OpenSession();
}

void UserIDMClient::CloseSession()
{
    USERIDM_HILOGD(MODULE_CLIENT, "CloseSession start");

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "CloseSession proxy is nullptr");
        return;
    }

    proxy->CloseSession();
}

int32_t UserIDMClient::GetAuthInfo(int32_t userId, AuthType authType, const std::shared_ptr<GetInfoCallback>& callback)
{
    USERIDM_HILOGD(MODULE_CLIENT, "GetAuthInfoById start");

    if (callback == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "GetAuthInfo proxy is nullptr");
        return FAIL;
    }

    sptr<IGetInfoCallback> callbackStub = new UserIDMGetInfoCallbackStub(callback);
    return proxy->GetAuthInfo(userId, authType, callbackStub);
}

int32_t UserIDMClient::GetAuthInfo(AuthType authType, const std::shared_ptr<GetInfoCallback>& napiCallback)
{
    USERIDM_HILOGD(MODULE_CLIENT, "GetAuthInfo start");

    if (napiCallback == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "GetAuthInfo proxy is nullptr");
        return FAIL;
    }

    sptr<IGetInfoCallback> callbackStub = new UserIDMGetInfoCallbackStub(napiCallback);
    return proxy->GetAuthInfo(authType, callbackStub);
}

int32_t UserIDMClient::GetSecInfo(int32_t userId, const std::shared_ptr<GetSecInfoCallback>& napiCallback)
{
    USERIDM_HILOGD(MODULE_CLIENT, "GetSecInfo start");

    if (napiCallback == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "GetSecInfo proxy is nullptr");
        return FAIL;
    }

    sptr<IGetSecInfoCallback> callbackStub = new UserIDMGetSecInfoCallbackStub(napiCallback);
    return proxy->GetSecInfo(userId, callbackStub);
}

void UserIDMClient::AddCredential(AddCredInfo& credInfo, const std::shared_ptr<IDMCallback>& napiCallback)
{
    USERIDM_HILOGD(MODULE_CLIENT, "AddCredential start");

    if (napiCallback == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "callback is nullptr");
        return;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "AddCredential proxy is nullptr");
        return;
    }

    sptr<IIDMCallback> callbackStub = new UserIDMCallbackStub(napiCallback);
    proxy->AddCredential(credInfo, callbackStub);
}

void UserIDMClient::UpdateCredential(AddCredInfo& credInfo, const std::shared_ptr<IDMCallback>& napiCallback)
{
    USERIDM_HILOGD(MODULE_CLIENT, "UpdateCredential start");

    if (napiCallback == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, " callback is nullptr");
        return;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "UpdateCredential proxy is nullptr");
        return;
    }

    sptr<IIDMCallback> callbackStub = new UserIDMCallbackStub(napiCallback);
    proxy->UpdateCredential(credInfo, callbackStub);
}

int32_t UserIDMClient::Cancel(uint64_t challenge)
{
    USERIDM_HILOGD(MODULE_CLIENT, "Cancel start");

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "Cancel proxy is nullptr");
        return FAIL;
    }

    return proxy->Cancel(challenge);
}

int32_t UserIDMClient::EnforceDelUser(int32_t userId, const std::shared_ptr<IDMCallback>& napiCallback)
{
    USERIDM_HILOGD(MODULE_CLIENT, "EnforceDelUser start");

    if (napiCallback == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, " callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "EnforceDelUser proxy is nullptr");
        return FAIL;
    }

    sptr<IIDMCallback> callbackStub = new UserIDMCallbackStub(napiCallback);
    return proxy->EnforceDelUser(userId, callbackStub);
}

void UserIDMClient::DelUser(std::vector<uint8_t> authToken, const std::shared_ptr<IDMCallback>& napiCallback)
{
    USERIDM_HILOGD(MODULE_CLIENT, "DelUser start");

    if (napiCallback == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "callback is nullptr");
        return;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "DelUser proxy is nullptr");
        return;
    }

    sptr<IIDMCallback> callbackStub = new UserIDMCallbackStub(napiCallback);
    proxy->DelUser(authToken, callbackStub);
}

void UserIDMClient::DelCred(uint64_t credentialId, std::vector<uint8_t> authToken,
    const std::shared_ptr<IDMCallback>& napiCallback)
{
    USERIDM_HILOGD(MODULE_CLIENT, "DelCred start");

    if (napiCallback == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "callback is nullptr");
        return;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        USERIDM_HILOGE(MODULE_CLIENT, "DelCred proxy is nullptr");
        return;
    }

    sptr<IIDMCallback> callbackStub = new UserIDMCallbackStub(napiCallback);
    proxy->DelCred(credentialId, authToken, callbackStub);
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
