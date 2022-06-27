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
#include "ipc_common.h"
#include "result_code.h"
#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const uint64_t BAD_CONTEXT_ID = 0;
    const int32_t INVALID_VERSION = -1;
    const int32_t CURRENT_VERSION = 0;
    const uint32_t AUTH_TRUST_LEVEL_SYS = 1;
    const std::string ACCESS_USER_AUTH_INTERNAL_PERMISSION = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
    const std::string ACCESS_BIOMETRIC_PERMISSION = "ohos.permission.ACCESS_BIOMETRIC";
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

int32_t UserAuthService::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start");
    bool checkRet = !IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        (authType == PIN || !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION));
    if (checkRet) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (authTrustLevel < ATL1 || authTrustLevel > ATL4) {
        IAM_LOGE("authTrustLevel is not in correct range");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    std::optional<int32_t> userId = std::nullopt;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get callingUserId");
        return FAIL;
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return FAIL;
    }
    uint32_t supportedAtl = AUTH_TRUST_LEVEL_SYS;
    int32_t result =
        hdi->GetAuthTrustLevel(userId.value(), static_cast<HDI::UserAuth::V1_0::AuthType>(authType), supportedAtl);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get current supported authTrustLevel from hdi, result = %{public}d", result);
        return result;
    }
    if (authTrustLevel > supportedAtl) {
        IAM_LOGE("the current authTrustLevel does not support");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    return SUCCESS;
}

void UserAuthService::GetProperty(std::optional<int32_t> userId, AuthType authType,
    const std::vector<Attributes::AttributeKey> &keys, sptr<GetExecutorPropertyCallback> &callback)
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

    if (IpcCommon::GetActiveAccountId(userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        callback->OnGetExecutorPropertyResult(FAIL, values);
        return;
    }
    auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId.value(), authType);
    if (credentialInfos.empty() || credentialInfos[0] == nullptr) {
        IAM_LOGE("credential info is incorrect");
        callback->OnGetExecutorPropertyResult(FAIL, values);
        return;
    }
    uint64_t executorIndex = credentialInfos[0]->GetExecutorIndex();
    uint64_t templateId = credentialInfos[0]->GetTemplateId();

    auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        callback->OnGetExecutorPropertyResult(FAIL, values);
        return;
    }
    Attributes attr;
    attr.SetUint32Value(Attributes::ATTR_AUTH_TYPE, static_cast<uint32_t>(authType));
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, templateId);
    attr.SetUint64Value(Attributes::ATTR_CALLER_UID, static_cast<uint64_t>(this->GetCallingUid()));

    int32_t result = resourceNode->GetProperty(attr, values);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get property, result = %{public}d", result);
    }
    callback->OnGetExecutorPropertyResult(result, values);
}

void UserAuthService::SetProperty(std::optional<int32_t> userId, AuthType authType, const Attributes &attributes,
    sptr<SetExecutorPropertyCallback> &callback)
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
    if (IpcCommon::GetActiveAccountId(userId) != SUCCESS) {
        IAM_LOGE("get userId failed");
        callback->OnSetExecutorPropertyResult(FAIL);
        return;
    }

    auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId.value(), authType);
    if (credentialInfos.empty() || credentialInfos[0] == nullptr) {
        IAM_LOGE("credential info is incorrect");
        callback->OnSetExecutorPropertyResult(FAIL);
        return;
    }
    uint64_t executorIndex = credentialInfos[0]->GetExecutorIndex();
    auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        callback->OnSetExecutorPropertyResult(FAIL);
        return;
    }
    int32_t result = resourceNode->SetProperty(attributes);
    if (result != SUCCESS) {
        IAM_LOGE("set property failed, result = %{public}d", result);
    }
    callback->OnSetExecutorPropertyResult(result);
}

uint64_t UserAuthService::AuthUser(std::optional<int32_t> userId, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallback> &callback)
{
    IAM_LOGI("start");
    Attributes extraInfo;

    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    if (authTrustLevel < ATL1 || authTrustLevel > ATL4) {
        IAM_LOGE("authTrustLevel is not in correct range");
        callback->OnAuthResult(TRUST_LEVEL_NOT_SUPPORT, extraInfo);
        return BAD_CONTEXT_ID;
    }
    bool checkRet = !IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        (authType == PIN || !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION));
    if (checkRet) {
        IAM_LOGE("failed to check permission");
        callback->OnAuthResult(CHECK_PERMISSION_FAILED, extraInfo);
        return BAD_CONTEXT_ID;
    }

    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        callback->OnAuthResult(FAIL, extraInfo);
        return BAD_CONTEXT_ID;
    }

    auto callingUid = static_cast<uint64_t>(this->GetCallingUid());
    auto context = ContextFactory::CreateSimpleAuthContext(userId.value(), challenge, authType, authTrustLevel,
        callingUid, callback);
    if (!ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        callback->OnAuthResult(FAIL, extraInfo);
        return BAD_CONTEXT_ID;
    }

    auto cleaner = ContextHelper::Cleaner(context);
    context->SetContextStopCallback(cleaner);

    if (!context->Start()) {
        IAM_LOGE("failed to start auth");
        callback->OnAuthResult(FAIL, extraInfo);
        cleaner();
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

uint64_t UserAuthService::Identify(const std::vector<uint8_t> &challenge, AuthType authType,
    sptr<UserAuthCallback> &callback)
{
    IAM_LOGI("start");
    Attributes extraInfo;

    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return BAD_CONTEXT_ID;
    }
    if (authType == PIN) {
        IAM_LOGE("pin not support");
        callback->OnIdentifyResult(TYPE_NOT_SUPPORT, extraInfo);
        return BAD_CONTEXT_ID;
    }

    auto callingUid = static_cast<uint64_t>(this->GetCallingUid());
    auto context = ContextFactory::CreateIdentifyContext(challenge, authType, callingUid, callback);
    if (!ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        callback->OnIdentifyResult(FAIL, extraInfo);
        return BAD_CONTEXT_ID;
    }

    auto cleaner = ContextHelper::Cleaner(context);
    context->SetContextStopCallback(cleaner);

    if (!context->Start()) {
        IAM_LOGE("failed to start identify");
        callback->OnIdentifyResult(FAIL, extraInfo);
        cleaner();
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

int32_t UserAuthService::CancelAuthOrIdentify(uint64_t contextId)
{
    IAM_LOGI("start");
    auto context = ContextPool::Instance().Select(contextId).lock();
    if (context == nullptr) {
        IAM_LOGE("context not exist");
        return FAIL;
    }

    if (!context->Stop()) {
        IAM_LOGE("failed to cancel auth or identify");
        return FAIL;
    }

    // try to delete contextId to prevent duplicate cancel success
    // it's possible that contextId is deleted before Stop() returns, so delete may fail
    if (!ContextPool::Instance().Delete(contextId)) {
        IAM_LOGI("failed to delete context");
    }
    return SUCCESS;
}

int32_t UserAuthService::GetVersion()
{
    IAM_LOGI("start");
    bool checkRet = !IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION);
    if (checkRet) {
        IAM_LOGE("failed to check permission");
        return INVALID_VERSION;
    }
    return CURRENT_VERSION;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS