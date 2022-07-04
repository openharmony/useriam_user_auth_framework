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

#include "iam_check.h"
#include "iam_logger.h"
#include "useridm_callback_stub.h"
#include "useridm_getinfo_callback_stub.h"
#include "useridm_getsecinfo_callback_stub.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<IUserIDM> UserIDMClient::GetUserIDMProxy()
{
    IAM_LOGD("GetUserIDMProxy start");

    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sam) {
        IAM_LOGE("failed to get systemAbilityManager");
        return nullptr;
    }

    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERIDM);
    if (!obj) {
        IAM_LOGE("failed to get remoteObject");
        return nullptr;
    }

    sptr<IRemoteObject::DeathRecipient> dr = new (std::nothrow) UserIDMDeathRecipient();
    IF_FALSE_LOGE_AND_RETURN_VAL(dr != nullptr, nullptr);
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        IAM_LOGE("Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<IUserIDM>(obj);
    deathRecipient_ = dr;

    IAM_LOGD("Succeed to connect manager service");
    return proxy_;
}

void UserIDMClient::ResetUserIDMProxy(const wptr<IRemoteObject>& remote)
{
    IAM_LOGD("ResetUserIDMProxy start");

    std::lock_guard<std::mutex> lock(mutex_);
    if (!proxy_) {
        IAM_LOGE("ResetUserIDMProxy proxy is nullptr");
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
    IAM_LOGD("OnRemoteDied start");

    if (remote == nullptr) {
        IAM_LOGE("OnRemoteDied failed, remote is nullptr");
        return;
    }

    UserIDMClient::GetInstance().ResetUserIDMProxy(remote);
    IAM_LOGE("UserIDMDeathRecipient::Recv death notice");
}

uint64_t UserIDMClient::OpenSession()
{
    IAM_LOGD("OpenSession start");

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("OpenSession proxy is nullptr");
        return FAIL;
    }
    return proxy->OpenSession();
}

void UserIDMClient::CloseSession()
{
    IAM_LOGD("CloseSession start");

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("CloseSession proxy is nullptr");
        return;
    }

    proxy->CloseSession();
}

int32_t UserIDMClient::GetAuthInfo(int32_t userId, AuthType authType, const std::shared_ptr<GetInfoCallback>& callback)
{
    IAM_LOGD("GetAuthInfoById start");

    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("GetAuthInfo proxy is nullptr");
        return FAIL;
    }

    sptr<IGetInfoCallback> callbackStub = new (std::nothrow) UserIDMGetInfoCallbackStub(callback);
    IF_FALSE_LOGE_AND_RETURN_VAL(callbackStub != nullptr, FAIL);
    return proxy->GetAuthInfo(userId, authType, callbackStub);
}

int32_t UserIDMClient::GetAuthInfo(AuthType authType, const std::shared_ptr<GetInfoCallback>& napiCallback)
{
    IAM_LOGD("GetAuthInfo start");

    if (napiCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("GetAuthInfo proxy is nullptr");
        return FAIL;
    }

    sptr<IGetInfoCallback> callbackStub = new (std::nothrow) UserIDMGetInfoCallbackStub(napiCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(callbackStub != nullptr, FAIL);
    return proxy->GetAuthInfo(authType, callbackStub);
}

int32_t UserIDMClient::GetSecInfo(int32_t userId, const std::shared_ptr<GetSecInfoCallback>& napiCallback)
{
    IAM_LOGD("GetSecInfo start");

    if (napiCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("GetSecInfo proxy is nullptr");
        return FAIL;
    }

    sptr<IGetSecInfoCallback> callbackStub = new (std::nothrow) UserIDMGetSecInfoCallbackStub(napiCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(callbackStub != nullptr, FAIL);
    return proxy->GetSecInfo(userId, callbackStub);
}

void UserIDMClient::AddCredential(AddCredInfo& credInfo, const std::shared_ptr<IDMCallback>& napiCallback)
{
    IAM_LOGD("AddCredential start");

    if (napiCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("AddCredential proxy is nullptr");
        return;
    }

    sptr<IIDMCallback> callbackStub = new (std::nothrow) UserIDMCallbackStub(napiCallback);
    IF_FALSE_LOGE_AND_RETURN(callbackStub != nullptr);
    proxy->AddCredential(credInfo, callbackStub);
}

void UserIDMClient::UpdateCredential(AddCredInfo& credInfo, const std::shared_ptr<IDMCallback>& napiCallback)
{
    IAM_LOGD("UpdateCredential start");

    if (napiCallback == nullptr) {
        IAM_LOGE(" callback is nullptr");
        return;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("UpdateCredential proxy is nullptr");
        return;
    }

    sptr<IIDMCallback> callbackStub = new (std::nothrow) UserIDMCallbackStub(napiCallback);
    IF_FALSE_LOGE_AND_RETURN(callbackStub != nullptr);
    proxy->UpdateCredential(credInfo, callbackStub);
}

int32_t UserIDMClient::Cancel(uint64_t challenge)
{
    IAM_LOGD("Cancel start");

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("Cancel proxy is nullptr");
        return FAIL;
    }

    return proxy->Cancel(challenge);
}

int32_t UserIDMClient::EnforceDelUser(int32_t userId, const std::shared_ptr<IDMCallback>& napiCallback)
{
    IAM_LOGD("EnforceDelUser start");

    if (napiCallback == nullptr) {
        IAM_LOGE(" callback is nullptr");
        return INVALID_PARAMETERS;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("EnforceDelUser proxy is nullptr");
        return FAIL;
    }

    sptr<IIDMCallback> callbackStub = new (std::nothrow) UserIDMCallbackStub(napiCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(callbackStub != nullptr, FAIL);
    return proxy->EnforceDelUser(userId, callbackStub);
}

void UserIDMClient::DelUser(std::vector<uint8_t> authToken, const std::shared_ptr<IDMCallback>& napiCallback)
{
    IAM_LOGD("DelUser start");

    if (napiCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("DelUser proxy is nullptr");
        return;
    }

    sptr<IIDMCallback> callbackStub = new (std::nothrow) UserIDMCallbackStub(napiCallback);
    IF_FALSE_LOGE_AND_RETURN(callbackStub != nullptr);
    proxy->DelUser(authToken, callbackStub);
}

void UserIDMClient::DelCred(uint64_t credentialId, std::vector<uint8_t> authToken,
    const std::shared_ptr<IDMCallback>& napiCallback)
{
    IAM_LOGD("DelCred start");

    if (napiCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    auto proxy = GetUserIDMProxy();
    if (proxy == nullptr) {
        IAM_LOGE("DelCred proxy is nullptr");
        return;
    }

    sptr<IIDMCallback> callbackStub = new (std::nothrow) UserIDMCallbackStub(napiCallback);
    IF_FALSE_LOGE_AND_RETURN(callbackStub != nullptr);
    proxy->DelCred(credentialId, authToken, callbackStub);
}
} // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
