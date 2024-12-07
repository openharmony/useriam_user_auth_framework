/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "user_auth_napi_client_impl.h"

#include "system_ability_definition.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "ipc_client_utils.h"
#include "modal_callback_service.h"
#include "user_auth_callback_service.h"

#define LOG_TAG "USER_AUTH_SDK"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<UserAuthInterface> UserAuthNapiClientImpl::GetProxy()
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

void UserAuthNapiClientImpl::ResetProxy(const wptr<IRemoteObject> &remote)
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

void UserAuthNapiClientImpl::UserAuthImplDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    CallbackManager::GetInstance().OnServiceDeath();
    UserAuthNapiClientImpl::Instance().ResetProxy(remote);
}

UserAuthNapiClientImpl &UserAuthNapiClientImpl::Instance()
{
    static UserAuthNapiClientImpl impl;
    return impl;
}

uint64_t UserAuthNapiClientImpl::BeginWidgetAuth(int32_t apiVersion, const AuthParamInner &authParam,
    const WidgetParamNapi &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback)
{
    IAM_LOGI("start, apiVersion: %{public}d authTypeSize: %{public}zu authTrustLevel: %{public}u userId:%{public}d",
        apiVersion, authParam.authTypes.size(), authParam.authTrustLevel, authParam.userId);

    AuthParamInner authParamInner = {
        .challenge = authParam.challenge,
        .authTypes = authParam.authTypes,
        .authTrustLevel = authParam.authTrustLevel,
        .reuseUnlockResult = authParam.reuseUnlockResult,
        .isUserIdSpecified = authParam.userId == INVALID_USER_ID ? false : true,
        .userId = authParam.userId,
    };
    WidgetParamInner widgetParamInner = {
        .title = widgetParam.title,
        .navigationButtonText = widgetParam.navigationButtonText,
        .windowMode = widgetParam.windowMode,
    };
    if (widgetParam.context != nullptr) {
        widgetParamInner.hasContext = true;
    }
    IAM_LOGI("has context: %{public}d", widgetParamInner.hasContext);
    return BeginWidgetAuthInner(apiVersion, authParamInner, widgetParamInner, callback, widgetParam.context);
}

uint64_t UserAuthNapiClientImpl::BeginWidgetAuthInner(int32_t apiVersion, const AuthParamInner &authParam,
    const WidgetParamInner &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback,
    const std::shared_ptr<AbilityRuntime::Context> context)
{
    if (!callback) {
        IAM_LOGE("auth callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return BAD_CONTEXT_ID;
    }

    // modal
    const std::shared_ptr<UserAuthModalCallback> &modalCallback = Common::MakeShared<UserAuthModalCallback>(context);

    sptr<UserAuthCallbackInterface> wrapper(new (std::nothrow) UserAuthCallbackService(callback));
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return BAD_CONTEXT_ID;
    }

    // modal
    sptr<ModalCallbackInterface> wrapperModal(new (std::nothrow) ModalCallbackService(modalCallback));
    if (wrapperModal == nullptr) {
        IAM_LOGE("failed to create wrapper for modal");
        Attributes extraInfo;
        callback->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);
        return BAD_CONTEXT_ID;
    }
    return proxy->AuthWidget(apiVersion, authParam, widgetParam, wrapper, wrapperModal);
}

int32_t UserAuthNapiClientImpl::CancelAuthentication(uint64_t contextId, int32_t cancelReason)
{
    IAM_LOGI("start");
    auto proxy = GetProxy();
    if (!proxy) {
        IAM_LOGE("proxy is nullptr");
        return GENERAL_ERROR;
    }

    return proxy->CancelAuthOrIdentify(contextId, cancelReason);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
