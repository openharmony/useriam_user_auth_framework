/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "auth_common.h"
#include "context_factory.h"
#include "context_helper.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "ipc_common.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "widget_client.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const uint64_t BAD_CONTEXT_ID = 0;
const int32_t MINIMUM_VERSION = 0;
const int32_t CURRENT_VERSION = 1;
const uint32_t AUTH_TRUST_LEVEL_SYS = 1;
void GetTemplatesByAuthType(int32_t userId, AuthType authType, std::vector<uint64_t> &templateIds)
{
    templateIds.clear();
    auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType);
    if (credentialInfos.empty()) {
        IAM_LOGE("user %{public}d has no credential type %{public}d", userId, authType);
        return;
    }
    
    templateIds.reserve(credentialInfos.size());
    for (auto &info : credentialInfos) {
        if (info == nullptr) {
            IAM_LOGE("info is nullptr");
            continue;
        }
        templateIds.push_back(info->GetTemplateId());
    }
}

bool IsTemplateIdListRequired(const std::vector<Attributes::AttributeKey> &keys)
{
    for (const auto &key : keys) {
        if (key == Attributes::AttributeKey::ATTR_PIN_SUB_TYPE ||
            key == Attributes::AttributeKey::ATTR_REMAIN_TIMES ||
            key == Attributes::AttributeKey::ATTR_FREEZING_TIME) {
            return true;
        }
    }
    return false;
}

void GetResourceNodeByType(AuthType authType, std::vector<std::weak_ptr<ResourceNode>> &authTypeNodes)
{
    authTypeNodes.clear();
    ResourceNodePool::Instance().Enumerate(
        [&authTypeNodes, authType](const std::weak_ptr<ResourceNode> &weakNode) {
            auto node = weakNode.lock();
            if (node == nullptr) {
                return;
            }
            if (node->GetAuthType() == authType) {
                authTypeNodes.push_back(node);
            }
        });
}
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
        hdi->GetAuthTrustLevel(userId, static_cast<HdiAuthType>(authType), supportedAtl);
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
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    Attributes values;

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        callback->OnGetExecutorPropertyResult(CHECK_PERMISSION_FAILED, values);
        return;
    }

    std::vector<uint64_t> templateIds;
    if (IsTemplateIdListRequired(keys)) {
        GetTemplatesByAuthType(userId, authType, templateIds);
        if (templateIds.size() == 0) {
            IAM_LOGE("template id list is required, but templateIds size is 0");
            callback->OnGetExecutorPropertyResult(NOT_ENROLLED, values);
            return;
        }
    }

    std::vector<std::weak_ptr<ResourceNode>> authTypeNodes;
    GetResourceNodeByType(authType, authTypeNodes);
    if (authTypeNodes.size() != 1) {
        IAM_LOGE("auth type %{public}d resource node num %{public}zu is not expected",
            authType, authTypeNodes.size());
        callback->OnGetExecutorPropertyResult(GENERAL_ERROR, values);
        return;
    }

    auto resourceNode = authTypeNodes[0].lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        callback->OnGetExecutorPropertyResult(GENERAL_ERROR, values);
        return;
    }

    std::vector<uint32_t> uint32Keys;
    uint32Keys.reserve(keys.size());
    for (auto &key : keys) {
        uint32Keys.push_back(static_cast<uint32_t>(key));
    }

    Attributes attr;
    attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);
    attr.SetUint64Value(Attributes::ATTR_CALLER_UID, static_cast<uint64_t>(this->GetCallingUid()));
    attr.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, uint32Keys);

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

    std::vector<std::weak_ptr<ResourceNode>> authTypeNodes;
    GetResourceNodeByType(authType, authTypeNodes);
    if (authTypeNodes.size() != 1) {
        IAM_LOGE("auth type %{public}d resource node num %{public}zu is not expected",
            authType, authTypeNodes.size());
        callback->OnSetExecutorPropertyResult(GENERAL_ERROR);
        return;
    }

    auto resourceNode = authTypeNodes[0].lock();
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

ResultCode UserAuthService::CheckWidgetNorthPermission(const std::vector<AuthType> &authTypeList,
    const AuthTrustLevel &authTrustValue)
{
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("CheckWidgetNorthPermission failed, no permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }

    for (auto authType : authTypeList) {
        switch (authType) {
            case AuthType::ALL :
            case AuthType::PIN :
                return ResultCode::SUCCESS;
            case AuthType::FACE:
            case AuthType::FINGERPRINT:
                if (authTrustValue == AuthTrustLevel::ATL4) {
                    IAM_LOGE("authType not match with trustLevel.");
                    return ResultCode::TRUST_LEVEL_NOT_SUPPORT;
                }
        }
    }
    return ResultCode::SUCCESS;
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
    para.endAfterFirstFail = true;
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
    para.endAfterFirstFail = false;
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

    if (context-> GetTokenId() != IpcCommon::GetAccessTokenId(*this)) {
        IAM_LOGE("failed to check tokenId");
        return INVALID_CONTEXT_ID;
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

uint64_t UserAuthService::AuthWidget(int32_t apiVersion, const AuthParam &authParam,
    const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");
    auto contextCallback = GetAuthContextCallback(authParam.challenge, authParam.authTrustLevel, callback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return BAD_CONTEXT_ID;
    }
    Attributes extraInfo;
    ResultCode checkRet = CheckWidgetNorthPermission(authParam.authType, authParam.authTrustLevel);
    if (checkRet != SUCCESS) {
        IAM_LOGE("CheckNorthPermission failed. errCode: %{public}d", checkRet);
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }
    int32_t userId;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceUserId(userId);
    if (!CheckValidSolution(userId, authParam.authType, authParam.authTrustLevel)) {
        IAM_LOGE("no valid solution, userId:%{public}d", userId);
        contextCallback->OnResult(ResultCode::NOT_ENROLLED, extraInfo);
        return BAD_CONTEXT_ID;
    }

    ContextFactory::AuthWidgetContextPara para;
    InitWidgetContextParam(userId, authParam, widgetParam, para);
    auto context = ContextFactory::CreateWidgetContext(para, contextCallback, userId, para.tokenId);
    const int32_t retryTimes = 3;
    if (!Insert2ContextPool(context, retryTimes)) {
        IAM_LOGE("insert context to pool failed, retry %{public}d times", retryTimes);
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
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

bool UserAuthService::Insert2ContextPool(const std::shared_ptr<Context> &context, int32_t retryTimes)
{
    bool ret = false;
    if (retryTimes <= 0) {
        retryTimes = 1;
    }
    for (auto i = 0; i < retryTimes; i++) {
        ret = ContextPool::Instance().Insert(context);
        if (ret) {
            break;
        }
    }
    return ret;
}

std::shared_ptr<ContextCallback> UserAuthService::GetAuthContextCallback(const std::vector<uint8_t> &challenge,
    AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return nullptr;
    }
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        callback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    auto callingUid = static_cast<uint64_t>(this->GetCallingUid());
    contextCallback->SetTraceCallingUid(callingUid);
    contextCallback->SetTraceAuthTrustLevel(authTrustLevel);
    return contextCallback;
}

int32_t UserAuthService::Notice(NoticeType noticeType, const std::string &eventData)
{
    IAM_LOGI("start");
    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("the caller is not a system application");
        return ResultCode::CHECK_SYSTEM_APP_FAILED;
    }

    bool checkRet = !IpcCommon::CheckPermission(*this, SUPPORT_USER_AUTH);
    if (checkRet) {
        IAM_LOGE("failed to check permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }
    return WidgetClient::Instance().OnNotice(noticeType, eventData);
}

int32_t UserAuthService::RegisterWidgetCallback(int32_t version, sptr<WidgetCallbackInterface> &callback)
{
    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("the caller is not a system application");
        return ResultCode::CHECK_SYSTEM_APP_FAILED;
    }

    if (!IpcCommon::CheckPermission(*this, SUPPORT_USER_AUTH)) {
        IAM_LOGE("CheckWidgetNorthPermission failed, no permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }

    int32_t userId;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        return ResultCode::GENERAL_ERROR;
    }

    uint32_t tokenId = IpcCommon::GetTokenId(*this);
    IAM_LOGE("RegisterWidgetCallback tokenId %{public}d", tokenId);

    int32_t curVersion = std::stoi(WidgetClient::Instance().GetVersion());
    if (version != curVersion) {
        return ResultCode::INVALID_PARAMETERS;
    }

    WidgetClient::Instance().SetWidgetCallback(callback);
    WidgetClient::Instance().SetUserAndTokenId(userId, tokenId);
    return ResultCode::SUCCESS;
}

void UserAuthService::InitWidgetContextParam(int32_t userId, const AuthParam &authParam,
    const WidgetParam &widgetParam, ContextFactory::AuthWidgetContextPara &para)
{
    for (auto &authType : authParam.authType) {
        ContextFactory::AuthWidgetContextPara::AuthProfile profile;
        if (!GetUserAuthProfile(userId, authType, profile)) {
            IAM_LOGE("get user auth profile failed");
        } else {
            para.authProfileMap[authType] = profile;
            if (authType == AuthType::PIN) {
                WidgetClient::Instance().SetPinSubType(static_cast<PinSubType>(profile.pinSubType));
            } else if (authType == AuthType::FINGERPRINT) {
                WidgetClient::Instance().SetSensorInfo(profile.sensorInfo);
            }
        }
    }
    para.userId = userId;
    para.tokenId = 0;
    para.callingUid = this->GetCallingUid();
    para.challenge = std::move(authParam.challenge);
    para.authTypeList = authParam.authType;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
}

bool UserAuthService::GetUserAuthProfile(int32_t userId, const AuthType &authType,
    ContextFactory::AuthWidgetContextPara::AuthProfile &profile)
{
    Attributes values;
    auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType);
    if (credentialInfos.empty() || credentialInfos[0] == nullptr) {
        IAM_LOGE("user %{public}d has no credential type %{public}d", userId, authType);
        return false;
    }
    uint64_t executorIndex = credentialInfos[0]->GetExecutorIndex();
    auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        return false;
    }

    std::vector<uint64_t> templateIds;
    templateIds.reserve(credentialInfos.size());
    for (auto &info : credentialInfos) {
        templateIds.push_back(info->GetTemplateId());
    }
    std::vector<uint32_t> uint32Keys = {
        Attributes::ATTR_SENSOR_INFO,
        Attributes::ATTR_REMAIN_TIMES,
        Attributes::ATTR_FREEZING_TIME
    };
    if (authType == AuthType::PIN) {
        uint32Keys.push_back(Attributes::ATTR_PIN_SUB_TYPE);
    }

    Attributes attr;
    attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);
    attr.SetUint64Value(Attributes::ATTR_CALLER_UID, static_cast<uint64_t>(this->GetCallingUid()));
    attr.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, uint32Keys);
    int32_t result = resourceNode->GetProperty(attr, values);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get property, result = %{public}d", result);
        return false;
    }
    return ParseAttributes(values, authType, profile);
}

bool UserAuthService::ParseAttributes(const Attributes &values, const AuthType &authType,
    ContextFactory::AuthWidgetContextPara::AuthProfile &profile)
{
    if (authType == AuthType::PIN) {
        if (!values.GetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, profile.pinSubType)) {
            IAM_LOGE("get ATTR_PIN_SUB_TYPE failed");
            return false;
        }
    }
    if (!values.GetStringValue(Attributes::ATTR_SENSOR_INFO, profile.sensorInfo)) {
        IAM_LOGE("get ATTR_SENSOR_INFO failed");
        return false;
    }
    if (!values.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, profile.remainTimes)) {
        IAM_LOGE("get ATTR_REMAIN_TIMES failed");
        return false;
    }
    if (!values.GetInt32Value(Attributes::ATTR_FREEZING_TIME, profile.freezingTime)) {
        IAM_LOGE("get ATTR_FREEZING_TIME failed");
        return false;
    }
    return true;
}

bool UserAuthService::CheckValidSolution(int32_t userId,
    const std::vector<AuthType> &authTypeList, const AuthTrustLevel &atl)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IAM_LOGE("hdi interface authTypeList start");
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return false;
    }
    std::vector<HdiAuthType> inputAuthType, validTypes;
    uint32_t inputAtl = atl;
    IAM_LOGE("hdi interface authTypeList size is:%{public}d", authTypeList.size());
    for (size_t index = 0; index < authTypeList.size(); index++) {
        inputAuthType.emplace_back(static_cast<HdiAuthType>(authTypeList[index]));
        IAM_LOGE("hdi interface authTypeList now index is:%{public}d", index);
    }
    int32_t result = hdi->GetValidSolution(userId, inputAuthType,
        inputAtl, validTypes);
    IAM_LOGE("hdi interface authTypeList middle");
    if (result != SUCCESS) {
        IAM_LOGE("failed to get current supported authTrustLevel from hdi result:%{public}d",
            result);
        return false;
    }
    return true;
}

bool UserAuthService::CheckCallerIsSystemApp()
{
    using namespace Security::AccessToken;
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool checkRet = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    uint32_t tokenId = this->GetCallingTokenID();
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType == TOKEN_HAP && !checkRet) {
        IAM_LOGE("the caller is not a system application");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS