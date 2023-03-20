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

#include "user_auth_service.h"

#include <cinttypes>

#include "accesstoken_kit.h"
#include "context_factory.h"
#include "context_helper.h"
#include "hdi_wrapper.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "ipc_common.h"
#include "iam_common_defines.h"
#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const uint64_t BAD_CONTEXT_ID = 0;
    const int32_t MINIMUM_VERSION = 0;
    const int32_t CURRENT_VERSION = 1;
    const uint32_t AUTH_TRUST_LEVEL_SYS = 1;
} // namespace

REGISTER_SYSTEM_ABILITY_BY_ID(UserAuthService, SUBSYS_USERIAM_SYS_ABILITY_USERAUTH, true);

UserAuthService::UserAuthService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
}

void UserAuthService::OnStart()
{
    IAM_LOGI("start service");
    if (!Publish(this)) {
        IAM_LOGE("failed to publish service");
    }
}

void UserAuthService::OnStop()
{
    IAM_LOGI("stop service");
}

int32_t UserAuthService::GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start");
    ResultCode checkRet = CheckServicePermission(authType);
    if (checkRet != SUCCESS) {
        IAM_LOGE("failed to check permission");
        return checkRet;
    }
    if (authTrustLevel != ATL1 && authTrustLevel != ATL2 && authTrustLevel != ATL3 && authTrustLevel != ATL4) {
        IAM_LOGE("authTrustLevel is not in correct range");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    int32_t userId;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get callingUserId");
        return GENERAL_ERROR;
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }
    uint32_t supportedAtl = AUTH_TRUST_LEVEL_SYS;
    int32_t result =
        hdi->GetAuthTrustLevel(userId, static_cast<HDI::UserAuth::V1_0::AuthType>(authType), supportedAtl);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get current supported authTrustLevel from hdi apiVersion:%{public}d result:%{public}d",
            apiVersion, result);
        return result;
    }
    if (authTrustLevel > supportedAtl) {
        IAM_LOGE("the current authTrustLevel does not support");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    return SUCCESS;
}

void UserAuthService::GetProperty(int32_t userId, AuthType authType,
    const std::vector<Attributes::AttributeKey> &keys, sptr<GetExecutorPropertyCallbackInterface> &callback)
{
    IAM_LOGI("start");
    Attributes values;
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        callback->OnGetExecutorPropertyResult(CHECK_PERMISSION_FAILED, values);
        return;
    }

    auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType);
    if (credentialInfos.empty() || credentialInfos[0] == nullptr) {
        IAM_LOGE("user %{public}d has no credential type %{public}d", userId, authType);
        callback->OnGetExecutorPropertyResult(NOT_ENROLLED, values);
        return;
    }
    uint64_t executorIndex = credentialInfos[0]->GetExecutorIndex();
    uint64_t templateId = credentialInfos[0]->GetTemplateId();

    auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        callback->OnGetExecutorPropertyResult(GENERAL_ERROR, values);
        return;
    }
    Attributes attr;
    attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, templateId);
    attr.SetUint64Value(Attributes::ATTR_CALLER_UID, static_cast<uint64_t>(this->GetCallingUid()));

    int32_t result = resourceNode->GetProperty(attr, values);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get property, result = %{public}d", result);
    }
    callback->OnGetExecutorPropertyResult(result, values);
}

void UserAuthService::SetProperty(int32_t userId, AuthType authType, const Attributes &attributes,
    sptr<SetExecutorPropertyCallbackInterface> &callback)
{
    IAM_LOGI("start");
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("permission check failed");
        callback->OnSetExecutorPropertyResult(CHECK_PERMISSION_FAILED);
        return;
    }

    auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType);
    if (credentialInfos.empty() || credentialInfos[0] == nullptr) {
        IAM_LOGE("credential info is incorrect");
        callback->OnSetExecutorPropertyResult(NOT_ENROLLED);
        return;
    }
    uint64_t executorIndex = credentialInfos[0]->GetExecutorIndex();
    auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        callback->OnSetExecutorPropertyResult(GENERAL_ERROR);
        return;
    }
    int32_t result = resourceNode->SetProperty(attributes);
    if (result != SUCCESS) {
        IAM_LOGE("set property failed, result = %{public}d", result);
    }
    callback->OnSetExecutorPropertyResult(result);
}

bool UserAuthService::CheckAuthPermission(bool isInnerCaller, AuthType authType)
{
    if (isInnerCaller && IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        return true;
    }
    if (!isInnerCaller && authType != PIN && IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        return true;
    }
    return false;
}

ResultCode UserAuthService::CheckNorthPermission(AuthType authType)
{
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("CheckNorthPermission failed, no permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (authType == PIN) {
        IAM_LOGE("CheckNorthPermission, type error");
        return TYPE_NOT_SUPPORT;
    }
    return SUCCESS;
}

ResultCode UserAuthService::CheckServicePermission(AuthType authType)
{
    if (IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        return SUCCESS;
    }
    return CheckNorthPermission(authType);
}

std::shared_ptr<ContextCallback> UserAuthService::GetAuthContextCallback(const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return nullptr;
    }
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    auto callingUid = static_cast<uint64_t>(this->GetCallingUid());
    contextCallback->SetTraceCallingUid(callingUid);
    contextCallback->SetTraceAuthType(authType);
    contextCallback->SetTraceAuthTrustLevel(authTrustLevel);
    return contextCallback;
}

uint64_t UserAuthService::Auth(int32_t apiVersion, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");
    auto contextCallback = GetAuthContextCallback(challenge, authType, authTrustLevel, callback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return BAD_CONTEXT_ID;
    }
    Attributes extraInfo;
    ResultCode checkRet = CheckNorthPermission(authType);
    if (checkRet != SUCCESS) {
        IAM_LOGE("CheckNorthPermission failed");
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }
    int32_t userId;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceUserId(userId);
    if (authTrustLevel != ATL1 && authTrustLevel != ATL2 && authTrustLevel != ATL3 && authTrustLevel != ATL4) {
        IAM_LOGE("authTrustLevel is not in correct range");
        contextCallback->OnResult(TRUST_LEVEL_NOT_SUPPORT, extraInfo);
        return BAD_CONTEXT_ID;
    }
    ContextFactory::AuthContextPara para = {};
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.userId = userId;
    para.authType = authType;
    para.atl = authTrustLevel;
    para.challenge = std::move(challenge);
    auto context = ContextFactory::CreateSimpleAuthContext(para, contextCallback);
    if (!ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }

    contextCallback->SetCleaner(ContextHelper::Cleaner(context));

    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("failed to start auth apiVersion:%{public}d errorCode:%{public}d", apiVersion, errorCode);
        contextCallback->OnResult(errorCode, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

uint64_t UserAuthService::AuthUser(int32_t userId, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");
    auto contextCallback = GetAuthContextCallback(challenge, authType, authTrustLevel, callback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceUserId(userId);
    Attributes extraInfo;
    if (authTrustLevel < ATL1 || authTrustLevel > ATL4) {
        IAM_LOGE("authTrustLevel is not in correct range");
        contextCallback->OnResult(TRUST_LEVEL_NOT_SUPPORT, extraInfo);
        return BAD_CONTEXT_ID;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return BAD_CONTEXT_ID;
    }
    ContextFactory::AuthContextPara para = {};
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.userId = userId;
    para.authType = authType;
    para.atl = authTrustLevel;
    para.challenge = std::move(challenge);
    auto context = ContextFactory::CreateSimpleAuthContext(para, contextCallback);
    if (!ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }

    contextCallback->SetCleaner(ContextHelper::Cleaner(context));

    if (!context->Start()) {
        IAM_LOGE("failed to start auth");
        contextCallback->OnResult(context->GetLatestError(), extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

uint64_t UserAuthService::Identify(const std::vector<uint8_t> &challenge, AuthType authType,
    sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");

    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_IDENTIFY);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    if (authType == PIN) {
        IAM_LOGE("pin not support");
        contextCallback->OnResult(TYPE_NOT_SUPPORT, extraInfo);
        return BAD_CONTEXT_ID;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return BAD_CONTEXT_ID;
    }

    ContextFactory::IdentifyContextPara para = {};
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.authType = authType;
    para.challenge = std::move(challenge);
    auto context = ContextFactory::CreateIdentifyContext(para, contextCallback);
    if (!ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }

    contextCallback->SetCleaner(ContextHelper::Cleaner(context));

    if (!context->Start()) {
        IAM_LOGE("failed to start identify");
        contextCallback->OnResult(context->GetLatestError(), extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

int32_t UserAuthService::CancelAuthOrIdentify(uint64_t contextId)
{
    IAM_LOGI("start");
    bool checkRet = !IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION);
    if (checkRet) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    auto context = ContextPool::Instance().Select(contextId).lock();
    if (context == nullptr) {
        IAM_LOGE("context not exist");
        return GENERAL_ERROR;
    }

    if (!context->Stop()) {
        IAM_LOGE("failed to cancel auth or identify");
        return context->GetLatestError();
    }

    return SUCCESS;
}

int32_t UserAuthService::GetVersion(int32_t &version)
{
    IAM_LOGI("start");
    version = MINIMUM_VERSION;
    bool checkRet = !IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION);
    if (checkRet) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    version = CURRENT_VERSION;
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS