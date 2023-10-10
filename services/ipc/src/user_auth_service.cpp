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
#include "hisysevent_adapter.h"

#include <cinttypes>

#include "accesstoken_kit.h"
#include "auth_common.h"
#include "auth_widget_helper.h"
#include "context_factory.h"
#include "auth_common.h"
#include "context_helper.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_time.h"
#include "ipc_common.h"
#include "ipc_skeleton.h"
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
const int32_t USERIAM_IPC_THREAD_NUM = 4;
const uint32_t MAX_AUTH_TYPE_SIZE = 3;

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
    IPCSkeleton::SetMaxWorkThreadNum(USERIAM_IPC_THREAD_NUM);
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

ResultCode UserAuthService::CheckWidgetNorthPermission()
{
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("CheckWidgetNorthPermission failed, no permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
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

ResultCode UserAuthService::CheckAuthWidgetParam(const AuthParam &authParam, const WidgetParam &widgetParam)
{
    if (authParam.authType.size() == 0 || authParam.authType.size() > MAX_AUTH_TYPE_SIZE) {
        IAM_LOGE("invalid authType size:%{public}zu", authParam.authType.size());
        return ResultCode::INVALID_PARAMETERS;
    }

    std::set<AuthType> authTypeChecker = {};
    for (auto &type : authParam.authType) {
        if (authTypeChecker.find(type) != authTypeChecker.end()) {
            IAM_LOGE("duplicate auth type");
            return ResultCode::INVALID_PARAMETERS;
        }
        switch (type) {
            case AuthType::PIN:
            case AuthType::FACE:
            case AuthType::FINGERPRINT:
                break;
            default:
                IAM_LOGE("invalid auth type");
                return ResultCode::TYPE_NOT_SUPPORT;
        }
        authTypeChecker.emplace(type);
    }

    if (authParam.authTrustLevel != AuthTrustLevel::ATL1 && authParam.authTrustLevel != AuthTrustLevel::ATL2
        && authParam.authTrustLevel != AuthTrustLevel::ATL3 && authParam.authTrustLevel != AuthTrustLevel::ATL4) {
        IAM_LOGE("authType not match with trustLevel: %{public}u", authParam.authTrustLevel);
        return ResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }

    if (widgetParam.title == "") {
        IAM_LOGE("title shouldn't be empty");
        return ResultCode::INVALID_PARAMETERS;
    }

    if (widgetParam.navigationButtonText != "") {
        IAM_LOGI("authParam.authType.size() = %{public}zu", authParam.authType.size());
        if (authParam.authType.size() != 1 || (authParam.authType[0] != AuthType::FACE &&
            authParam.authType[0] != AuthType::FINGERPRINT)) {
            IAM_LOGE("navigationButtonText check fail");
            return ResultCode::INVALID_PARAMETERS;
        }
    }

    if (widgetParam.windowMode == FULLSCREEN && authParam.authType.size() == 1 &&
        (authParam.authType[0] == AuthType::FACE || authParam.authType[0] == AuthType::FINGERPRINT)) {
        IAM_LOGE("Single fingerprint or single face does not support full screen");
        return ResultCode::GENERAL_ERROR;
    }
    return ResultCode::SUCCESS;
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

    if (context->GetTokenId() != IpcCommon::GetAccessTokenId(*this)) {
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

ResultCode UserAuthService::CheckParam(const AuthParam &authParam, const WidgetParam &widgetParam)
{
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP) &&
        widgetParam.windowMode != WindowModeType::UNKNOWN_WINDOW_MODE) {
        IAM_LOGE("normal app can't set window mode.");
        return INVALID_PARAMETERS;
    }
    ResultCode checkRet = CheckWidgetNorthPermission();
    if (checkRet != SUCCESS) {
        IAM_LOGE("CheckWidgetNorthPermission failed. errCode: %{public}d", checkRet);
        return checkRet;
    }
    checkRet = CheckAuthWidgetParam(authParam, widgetParam);
    if (checkRet != SUCCESS) {
        IAM_LOGE("parameter failed. errCode: %{public}d", checkRet);
        return checkRet;
    }
    return SUCCESS;
}

uint64_t UserAuthService::AuthWidget(int32_t apiVersion, const AuthParam &authParam,
    const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");
    auto contextCallback = GetAuthContextCallback(authParam, widgetParam, callback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return BAD_CONTEXT_ID;
    }
    Attributes extraInfo;
    ResultCode checkRet = CheckParam(authParam, widgetParam);
    if (checkRet != SUCCESS) {
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
    int32_t ret = AuthWidgetHelper::CheckValidSolution(userId, authParam.authType, authParam.authTrustLevel);
    if (ret != SUCCESS) {
        contextCallback->OnResult(ret, extraInfo);
        return BAD_CONTEXT_ID;
    }

    ContextFactory::AuthWidgetContextPara para;
    para.userId = userId;
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.callingUid = GetCallingUid();
    if (!AuthWidgetHelper::InitWidgetContextParam(userId, authParam, widgetParam, para)) {
        IAM_LOGE("init widgetContext failed");
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    auto context = ContextFactory::CreateWidgetContext(para, contextCallback);
    if (!Insert2ContextPool(context)) {
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
    IAM_LOGI("authWidget end, receive message success.");
    return context->GetContextId();
}

bool UserAuthService::Insert2ContextPool(const std::shared_ptr<Context> &context)
{
    bool ret = false;
    const int32_t retryTimes = 3;
    for (auto i = 0; i < retryTimes; i++) {
        ret = ContextPool::Instance().Insert(context);
        if (ret) {
            break;
        }
    }
    IAM_LOGI("insert context to pool, retry %{public}d times", retryTimes);
    return ret;
}

std::shared_ptr<ContextCallback> UserAuthService::GetAuthContextCallback(const AuthParam &authParam,
    const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback)
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
    contextCallback->SetTraceAuthTrustLevel(authParam.authTrustLevel);

    uint32_t authWidgetType = 0;
    for (const auto authType : authParam.authType) {
        authWidgetType |= static_cast<uint32_t>(authType);
    }
    static const uint32_t BIT_WINDOW_MODE = 0x40000000;
    if (widgetParam.windowMode == FULLSCREEN) {
        authWidgetType |= BIT_WINDOW_MODE;
    }
    static const uint32_t BIT_NAVIGATION = 0x80000000;
    if (!widgetParam.navigationButtonText.empty()) {
        authWidgetType |= BIT_NAVIGATION;
    }
    IAM_LOGE("SetTraceAuthWidgetType %{public}u", authWidgetType);
    contextCallback->SetTraceAuthWidgetType(authWidgetType);

    return contextCallback;
}

int32_t UserAuthService::Notice(NoticeType noticeType, const std::string &eventData)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP)) {
        IAM_LOGE("the caller is not a system application");
        return ResultCode::CHECK_SYSTEM_APP_FAILED;
    }

    if (!IpcCommon::CheckPermission(*this, SUPPORT_USER_AUTH)) {
        IAM_LOGE("failed to check permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }
    return WidgetClient::Instance().OnNotice(noticeType, eventData);
}

int32_t UserAuthService::RegisterWidgetCallback(int32_t version, sptr<WidgetCallbackInterface> &callback)
{
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP)) {
        IAM_LOGE("the caller is not a system application");
        return ResultCode::CHECK_SYSTEM_APP_FAILED;
    }

    if (!IpcCommon::CheckPermission(*this, SUPPORT_USER_AUTH)) {
        IAM_LOGE("CheckWidgetNorthPermission failed, no permission");
        return ResultCode::CHECK_PERMISSION_FAILED;
    }

    uint32_t tokenId = IpcCommon::GetTokenId(*this);
    IAM_LOGE("RegisterWidgetCallback tokenId %{public}u", tokenId);

    int32_t curVersion = std::stoi(NOTICE_VERSION_STR);
    if (version != curVersion) {
        return ResultCode::INVALID_PARAMETERS;
    }
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }
    WidgetClient::Instance().SetWidgetCallback(callback);
    WidgetClient::Instance().SetAuthTokenId(tokenId);
    return ResultCode::SUCCESS;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS