/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "auth_common.h"
#include "callback_manager.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "ipc_client_utils.h"
#include "user_auth_callback_service.h"
#include "widget_callback_service.h"

#define LOG_TAG "USER_AUTH_SDK"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class NorthAuthenticationCallback : public AuthenticationCallback, public NoCopyable {
public:
    explicit NorthAuthenticationCallback(std::shared_ptr<AuthenticationCallback> innerCallback);
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    std::shared_ptr<AuthenticationCallback> innerCallback_ = nullptr;
};

NorthAuthenticationCallback::NorthAuthenticationCallback(std::shared_ptr<AuthenticationCallback> innerCallback)
    : innerCallback_(innerCallback) {};

void NorthAuthenticationCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    if (module == AuthType::FACE) {
        if (acquireInfo == 0 || acquireInfo > FACE_AUTH_TIP_MAX) {
            IAM_LOGI("skip undefined face auth tip %{public}u", acquireInfo);
            return;
        }
    } else if (module == AuthType::FINGERPRINT) {
        if (acquireInfo > FINGERPRINT_AUTH_TIP_MAX) {
            IAM_LOGI("skip undefined fingerprint auth tip %{public}u", acquireInfo);
            return;
        }
    }

    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

void NorthAuthenticationCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    innerCallback_->OnResult(result, extraInfo);
}
} // namespace

int32_t UserAuthClientImpl::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start, authType:%{public}d authTrustLevel:%{public}u", authType, authTrustLevel);
    return GetAvailableStatus(INT32_MAX, authType, authTrustLevel);
}

int32_t UserAuthClientImpl::GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start, apiVersion:%{public}d authType:%{public}d authTrustLevel:%{public}u",
        apiVersion, authType, authTrustLevel);
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
    IAM_LOGI("start, userId:%{public}d authType:%{public}d", userId, request.authType);
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

    sptr<GetExecutorPropertyCallbackInterface> wrapper(
        new (std::nothrow) GetExecutorPropertyCallbackService(callback));
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
    Attributes attr;

    std::vector<uint8_t> extraInfo;
    bool getArrayRet = request.attrs.GetUint8ArrayValue(static_cast<Attributes::AttributeKey>(key), extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getArrayRet, GENERAL_ERROR);

    bool setModeRet = attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, static_cast<uint32_t>(key));
    IF_FALSE_LOGE_AND_RETURN_VAL(setModeRet, GENERAL_ERROR);

    bool setArrayRet = attr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(setArrayRet, GENERAL_ERROR);

    sptr<SetExecutorPropertyCallbackInterface> wrapper(
        new (std::nothrow) SetExecutorPropertyCallbackService(callback));
    IF_FALSE_LOGE_AND_RETURN_VAL(wrapper != nullptr, GENERAL_ERROR);
    proxy->SetProperty(userId, request.authType, attr, wrapper);
    return SUCCESS;
}

void UserAuthClientImpl::SetProperty(int32_t userId, const SetPropertyRequest &request,
    const std::shared_ptr<SetPropCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d", userId, request.authType);
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

uint64_t UserAuthClientImpl::BeginAuthentication(const AuthParam &authParam,
    const std::shared_ptr<AuthenticationCallback> &callback)
{
    IAM_LOGI("start, userId:%{public}d authType:%{public}d atl:%{public}u remoteAuthParamHasValue:%{public}s",
        authParam.userId, authParam.authType, authParam.authTrustLevel,
        Common::GetBoolStr(authParam.remoteAuthParam.has_value()));
    if (authParam.remoteAuthParam.has_value()) {
        IAM_LOGI("verifierNetworkIdHasValue:%{public}s collectorNetworkIdHasValue:%{public}s"
            "collectorTokenIdHasValue:%{public}s",
            Common::GetBoolStr(authParam.remoteAuthParam->verifierNetworkId.has_value()),
            Common::GetBoolStr(authParam.remoteAuthParam->collectorNetworkId.has_value()),
            Common::GetBoolStr(authParam.remoteAuthParam->collectorTokenId.has_value()));
    }

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

    sptr<UserAuthCallbackInterface> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }
    AuthParamInner authParamInner = {
        .userId = authParam.userId,
        .challenge = authParam.challenge,
        .authType = authParam.authType,
        .authTrustLevel = authParam.authTrustLevel,
        .authIntent = authParam.authIntent
    };
    std::optional<RemoteAuthParam> remoteAuthParam = authParam.remoteAuthParam;
    return proxy->AuthUser(authParamInner, remoteAuthParam, wrapper);
}

uint64_t UserAuthClientImpl::BeginNorthAuthentication(int32_t apiVersion, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel atl, const std::shared_ptr<AuthenticationCallback> &callback)
{
    IAM_LOGI("start, apiVersion:%{public}d authType:%{public}d atl:%{public}u", apiVersion, authType, atl);
    if (!callback) {
        IAM_LOGE("auth callback is nullptr");
        return INVALID_SESSION_ID;
    }

    auto northCallback = Common::MakeShared<NorthAuthenticationCallback>(callback);
    if (!northCallback) {
        IAM_LOGE("auth callback is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return INVALID_SESSION_ID;
    }

    sptr<UserAuthCallbackInterface> wrapper(new (std::nothrow) UserAuthCallbackService(northCallback));
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
    IAM_LOGI("start");
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
    IAM_LOGI("start, authType:%{public}d", authType);
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

    sptr<UserAuthCallbackInterface> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
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
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->CancelAuthOrIdentify(contextId);
}

int32_t UserAuthClientImpl::GetVersion(int32_t &version)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->GetVersion(version);
}

int32_t UserAuthClientImpl::SetGlobalConfigParam(const GlobalConfigParam &param)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->SetGlobalConfigParam(param);
}

sptr<UserAuthInterface> UserAuthClientImpl::GetProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH);
    if (obj == nullptr) {
        IAM_LOGE("remote object is null");
        return proxy_;
    }
    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) UserAuthImplDeathRecipient());
    if ((dr == nullptr) || (obj->IsProxyObject() && !obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient fail");
        return proxy_;
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
    CallbackManager::GetInstance().OnServiceDeath();
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

uint64_t UserAuthClientImpl::BeginWidgetAuth(int32_t apiVersion, const AuthParamInner &authParam,
    const WidgetParam &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback)
{
    IAM_LOGI("start, apiVersion:%{public}d authTypeSize:%{public}zu authTrustLevel:%{public}u",
        apiVersion, authParam.authTypes.size(), authParam.authTrustLevel);
    // parameter verification
    if (!callback) {
        IAM_LOGE("auth callback is nullptr");
        return INVALID_SESSION_ID;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return INVALID_SESSION_ID;
    }

    sptr<UserAuthCallbackInterface> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return INVALID_SESSION_ID;
    }
    return proxy->AuthWidget(apiVersion, authParam, widgetParam, wrapper);
}

int32_t UserAuthClientImpl::SetWidgetCallback(int32_t version, const std::shared_ptr<IUserAuthWidgetCallback> &callback)
{
    IAM_LOGI("start, version:%{public}d", version);
    if (!callback) {
        IAM_LOGE("widget callback is nullptr");
        return GENERAL_ERROR;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    sptr<WidgetCallbackInterface> wrapper(new (std::nothrow) WidgetCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return GENERAL_ERROR;
    }
    return proxy->RegisterWidgetCallback(version, wrapper);
}

int32_t UserAuthClientImpl::Notice(NoticeType noticeType, const std::string &eventData)
{
    IAM_LOGI("start, noticeType:%{public}d", noticeType);
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }
    IAM_LOGI("UserAuthClientImpl::Notice noticeType:%{public}d, eventDat:%{public}s",
        static_cast<int32_t>(noticeType), eventData.c_str());
    return proxy->Notice(noticeType, eventData);
}

int32_t UserAuthClientImpl::GetEnrolledState(int32_t apiVersion, AuthType authType, EnrolledState &enrolledState)
{
    IAM_LOGI("start, apiVersion:%{public}d authType:%{public}d ", apiVersion, authType);
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }
    int32_t ret = proxy->GetEnrolledState(apiVersion, authType, enrolledState);
    if (ret != SUCCESS) {
        IAM_LOGE("proxy GetEnrolledState failed");
        return ret;
    }
    return ret;
}

int32_t UserAuthClientImpl::RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
    const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGI("start");
    if (!listener) {
        IAM_LOGE("listener is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret = proxy->RegistUserAuthSuccessEventListener(authType, listener);
    if (ret != SUCCESS) {
        IAM_LOGE("Regist userAuth success event listener failed");
        return ret;
    }

    return SUCCESS;
}

int32_t UserAuthClientImpl::UnRegistUserAuthSuccessEventListener(const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGI("start");
    if (!listener) {
        IAM_LOGE("listener is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    int32_t ret = proxy->UnRegistUserAuthSuccessEventListener(listener);
    if (ret != SUCCESS) {
        IAM_LOGE("unRegist userAuth success event listener failed");
        return ret;
    }

    return SUCCESS;
}

int32_t UserAuthClientImpl::PrepareRemoteAuth(const std::string &networkId,
    const std::shared_ptr<PrepareRemoteAuthCallback> &callback)
{
    IAM_LOGI("start");
    if (!callback) {
        IAM_LOGE("prepare remote auth callback is nullptr");
        return GENERAL_ERROR;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        callback->OnResult(GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    sptr<UserAuthCallbackInterface> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        callback->OnResult(GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    return proxy->PrepareRemoteAuth(networkId, wrapper);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
