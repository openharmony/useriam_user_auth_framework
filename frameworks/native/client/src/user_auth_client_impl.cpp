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

#include "user_auth_client_impl.h"

#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "ipc_client_utils.h"
#include "user_auth_callback_service.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SDK
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t VENDOR_COMMAND_BASE = 10000;
}
int32_t UserAuthClientImpl::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel)
{
    return GetAvailableStatus(INT32_MAX, authType, authTrustLevel);
}

int32_t UserAuthClientImpl::GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel)
{
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->GetAvailableStatus(apiVersion, authType, authTrustLevel);
}

void UserAuthClientImpl::GetProperty(int32_t userId, const GetPropertyRequest &request,
    const std::shared_ptr<GetPropCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("get prop callback is nullptr");
        return;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    sptr<GetExecutorPropertyCallbackInterface> wrapper =
        new (std::nothrow) GetExecutorPropertyCallbackService(callback);
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    proxy->GetProperty(userId, request.authType, request.keys, wrapper);
}

ResultCode UserAuthClientImpl::SetPropertyInner(int32_t userId, const SetPropertyRequest &request,
    const std::shared_ptr<SetPropCallback> &callback)
{
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    auto keys = request.attrs.GetKeys();
    IF_FALSE_LOGE_AND_RETURN_VAL(keys.size() == 1, GENERAL_ERROR);

    Attributes::AttributeKey key = keys[0];
    uint32_t keyValue = static_cast<uint32_t>(key);
    IF_FALSE_LOGE_AND_RETURN_VAL(keyValue == PROPERTY_INIT_ALGORITHM, GENERAL_ERROR);
    keyValue = keyValue + VENDOR_COMMAND_BASE;
    Attributes attr;

    std::vector<uint8_t> extraInfo;
    bool getArrayRet = request.attrs.GetUint8ArrayValue(static_cast<Attributes::AttributeKey>(key), extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getArrayRet, GENERAL_ERROR);

    bool setModeRet = attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, keyValue);
    IF_FALSE_LOGE_AND_RETURN_VAL(setModeRet, GENERAL_ERROR);

    bool setArrayRet = attr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(setArrayRet, GENERAL_ERROR);

    sptr<SetExecutorPropertyCallbackInterface> wrapper =
        new (std::nothrow) SetExecutorPropertyCallbackService(callback);
    IF_FALSE_LOGE_AND_RETURN_VAL(wrapper != nullptr, GENERAL_ERROR);
    proxy->SetProperty(userId, request.authType, attr, wrapper);
    return SUCCESS;
}


void UserAuthClientImpl::SetProperty(int32_t userId, const SetPropertyRequest &request,
    const std::shared_ptr<SetPropCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("set prop callback is nullptr");
        return;
    }

    ResultCode result = SetPropertyInner(userId, request, callback);
    if (result != SUCCESS) {
        IAM_LOGE("result is not success");
        Attributes retExtraInfo;
        callback->OnResult(GENERAL_ERROR, retExtraInfo);
        return;
    }
}

uint64_t UserAuthClientImpl::BeginAuthentication(int32_t userId, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel atl, const std::shared_ptr<AuthenticationCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("auth callback is nullptr");
        return INVALID_SESSION_ID;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }

    sptr<UserAuthCallbackInterface> wrapper = new (std::nothrow) UserAuthCallbackService(callback);
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }
    return proxy->AuthUser(userId, challenge, authType, atl, wrapper);
}

uint64_t UserAuthClientImpl::BeginNorthAuthentication(int32_t apiVersion, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel atl, const std::shared_ptr<AuthenticationCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("auth callback is nullptr");
        return INVALID_SESSION_ID;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }

    sptr<UserAuthCallbackInterface> wrapper = new (std::nothrow) UserAuthCallbackService(callback);
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }
    return proxy->Auth(apiVersion, challenge, authType, atl, wrapper);
}

int32_t UserAuthClientImpl::CancelAuthentication(uint64_t contextId)
{
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->CancelAuthOrIdentify(contextId);
}

uint64_t UserAuthClientImpl::BeginIdentification(const std::vector<uint8_t> &challenge, AuthType authType,
    const std::shared_ptr<IdentificationCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("identify callback is nullptr");
        return INVALID_SESSION_ID;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }

    sptr<UserAuthCallbackInterface> wrapper = new (std::nothrow) UserAuthCallbackService(callback);
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }
    return proxy->Identify(challenge, authType, wrapper);
}

int32_t UserAuthClientImpl::CancelIdentification(uint64_t contextId)
{
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->CancelAuthOrIdentify(contextId);
}

int32_t UserAuthClientImpl::GetVersion(int32_t &version)
{
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->GetVersion(version);
}

sptr<UserAuthInterface> UserAuthClientImpl::GetProxy()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    if (obj == nullptr) {
        IAM_LOGE("remote object is null");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new (std::nothrow) UserAuthImplDeathRecipient();
    if ((dr == nullptr) || (obj->IsProxyObject() && !obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient fail");
        return nullptr;
    }

    proxy_ = iface_cast<UserAuthInterface>(obj);
    deathRecipient_ = dr;
    return proxy_;
}

void UserAuthClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
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

void UserAuthClientImpl::UserAuthImplDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    UserAuthClientImpl::Instance().ResetProxy(remote);
}

UserAuthClientImpl &UserAuthClientImpl::Instance()
{
    static UserAuthClientImpl impl;
    return impl;
}

UserAuthClient &UserAuthClient::GetInstance()
{
    return UserAuthClientImpl::Instance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS