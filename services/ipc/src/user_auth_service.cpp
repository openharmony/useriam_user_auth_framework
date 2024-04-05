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

#include "user_auth_service.h"
#include "hisysevent_adapter.h"

#include <cinttypes>

#include "accesstoken_kit.h"
#include "auth_common.h"
#include "auth_event_listener_manager.h"
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
#include "system_param_manager.h"
#include "widget_client.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
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
    SystemParamManager::GetInstance().Start();
}

void UserAuthService::OnStop()
{
    IAM_LOGI("stop service");
}

bool UserAuthService::CheckAuthTrustLevel(AuthTrustLevel authTrustLevel)
{
    if ((authTrustLevel != ATL1) && (authTrustLevel != ATL2) &&
        (authTrustLevel != ATL3) && (authTrustLevel != ATL4)) {
        IAM_LOGE("authTrustLevel not support %{public}u", authTrustLevel);
        return false;
    }
    return true;
}

int32_t UserAuthService::GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if ((apiVersion <= API_VERSION_8 && authType == PIN) ||
        !SystemParamManager::GetInstance().IsAuthTypeEnable(authType)) {
        IAM_LOGE("authType not support");
        return TYPE_NOT_SUPPORT;
    }
    if (!CheckAuthTrustLevel(authTrustLevel)) {
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
    uint32_t outValue = AUTH_TRUST_LEVEL_SYS;
    int32_t result =
        hdi->GetAuthTrustLevel(userId, static_cast<HdiAuthType>(authType), outValue);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get current supported authTrustLevel from hdi apiVersion:%{public}d result:%{public}d",
            apiVersion, result);
        return result;
    }
    static const uint32_t TWO_BYTE = 16;
    uint16_t supportedAtl = outValue & 0xffff;
    uint16_t resultOfCredState = (outValue >> TWO_BYTE) & 0xffff;
    if (authTrustLevel > supportedAtl) {
        IAM_LOGE("the current authTrustLevel does not support");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    IAM_LOGI("resultOfCredState is %{public}d", resultOfCredState);
    return resultOfCredState;
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
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);
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

std::shared_ptr<ContextCallback> UserAuthService::GetAuthContextCallback(int32_t apiVersion,
    const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return nullptr;
    }
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_ALL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    contextCallback->SetTraceAuthType(authType);
    contextCallback->SetTraceAuthTrustLevel(authTrustLevel);
    contextCallback->SetTraceAuthWidgetType(authType);
    contextCallback->SetTraceSdkVersion(apiVersion);
    return contextCallback;
}

int32_t UserAuthService::CheckAuthPermissionAndParam(int32_t authType, bool isBundleName,
    const std::string &callerName, AuthTrustLevel authTrustLevel)
{
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (isBundleName && (!IpcCommon::CheckForegroundApplication(callerName))) {
        IAM_LOGE("failed to check foreground application");
        return CHECK_PERMISSION_FAILED;
    }
    if ((authType == PIN) || !SystemParamManager::GetInstance().IsAuthTypeEnable(authType)) {
        IAM_LOGE("authType not support");
        return TYPE_NOT_SUPPORT;
    }
    if (!CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("authTrustLevel is not in correct range");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    return SUCCESS;
}

uint64_t UserAuthService::Auth(int32_t apiVersion, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");
    auto contextCallback = GetAuthContextCallback(apiVersion, challenge, authType, authTrustLevel, callback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return BAD_CONTEXT_ID;
    }
    bool isBundleName = false;
    std::string callerName = "";
    Attributes extraInfo;
    int32_t callerType = 0;
    if ((!IpcCommon::GetCallerName(*this, isBundleName, callerName, callerType)) && isBundleName) {
        IAM_LOGE("get bundle name fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    int32_t checkRet = CheckAuthPermissionAndParam(authType, isBundleName, callerName, authTrustLevel);
    if (checkRet != SUCCESS) {
        IAM_LOGE("check auth permission and param fail");
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
    Authentication::AuthenticationPara para = {};
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.userId = userId;
    para.authType = authType;
    para.atl = authTrustLevel;
    para.challenge = std::move(challenge);
    para.endAfterFirstFail = true;
    if (isBundleName) {
        para.callerName = "B_" + callerName;
    } else {
        para.callerName = "N_" + callerName;
    }
    para.sdkVersion = apiVersion;
    return StartAuthContext(apiVersion, para, contextCallback);
}

uint64_t UserAuthService::StartAuthContext(int32_t apiVersion, Authentication::AuthenticationPara para,
    const std::shared_ptr<ContextCallback> &contextCallback)
{
    Attributes extraInfo;
    auto context = ContextFactory::CreateSimpleAuthContext(para, contextCallback);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    contextCallback->SetTraceAuthContextId(context->GetContextId());
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));

    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("failed to start auth apiVersion:%{public}d errorCode:%{public}d", apiVersion, errorCode);
        contextCallback->OnResult(errorCode, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

bool UserAuthService::CheckAuthPermissionAndParam(AuthType authType, AuthTrustLevel authTrustLevel,
    const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo)
{
    if (!CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("authTrustLevel is not in correct range");
        contextCallback->OnResult(TRUST_LEVEL_NOT_SUPPORT, extraInfo);
        return false;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return false;
    }
    if (!SystemParamManager::GetInstance().IsAuthTypeEnable(authType)) {
        IAM_LOGE("auth type not support");
        contextCallback->OnResult(TYPE_NOT_SUPPORT, extraInfo);
        return false;
    }
    return true;
}

uint64_t UserAuthService::AuthUser(int32_t userId, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");
    auto contextCallback = GetAuthContextCallback(INNER_API_VERSION_10000, challenge, authType, authTrustLevel,
        callback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceUserId(userId);
    Attributes extraInfo;
    bool isBundleName = false;
    std::string callerName = "";
    int32_t callerType = 0;
    if ((!IpcCommon::GetCallerName(*this, isBundleName, callerName, callerType)) && isBundleName) {
        IAM_LOGE("get bundle name fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    if (CheckAuthPermissionAndParam(authType, authTrustLevel, contextCallback, extraInfo) == false) {
        return BAD_CONTEXT_ID;
    }
    Authentication::AuthenticationPara para = {};
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.userId = userId;
    para.authType = authType;
    para.atl = authTrustLevel;
    para.challenge = std::move(challenge);
    para.endAfterFirstFail = false;
    if (isBundleName) {
        para.callerName = "B_" + callerName;
    } else {
        para.callerName = "N_" + callerName;
    }
    para.callerType = callerType;
    para.sdkVersion = INNER_API_VERSION_10000;
    return StartAuthContext(INNER_API_VERSION_10000, para, contextCallback);
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
    if ((authType == PIN) || !SystemParamManager::GetInstance().IsAuthTypeEnable(authType)) {
        IAM_LOGE("type not support %{public}d", authType);
        contextCallback->OnResult(TYPE_NOT_SUPPORT, extraInfo);
        return BAD_CONTEXT_ID;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return BAD_CONTEXT_ID;
    }

    Identification::IdentificationPara para = {};
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

int32_t UserAuthService::CheckAuthWidgetType(const std::vector<AuthType> &authType)
{
    if (authType.empty() || (authType.size() > MAX_AUTH_TYPE_SIZE)) {
        IAM_LOGE("invalid authType size:%{public}zu", authType.size());
        return INVALID_PARAMETERS;
    }
    for (auto &type : authType) {
        if ((type != AuthType::PIN) && (type != AuthType::FACE) && (type != AuthType::FINGERPRINT)) {
            IAM_LOGE("unsupport auth type %{public}d", type);
            return TYPE_NOT_SUPPORT;
        }
    }
    std::set<AuthType> typeChecker(authType.begin(), authType.end());
    if (typeChecker.size() != authType.size()) {
        IAM_LOGE("duplicate auth type");
        return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

bool UserAuthService::CheckSingeFaceOrFinger(const std::vector<AuthType> &authType)
{
    const size_t sizeOne = 1;
    const size_t type0 = 0;
    if (authType.size() != sizeOne) {
        return false;
    }
    if (authType[type0] == AuthType::FACE) {
        return true;
    }
    if (authType[type0] == AuthType::FINGERPRINT) {
        return true;
    }
    return false;
}

int32_t UserAuthService::CheckAuthPermissionAndParam(int32_t userId, const AuthParam &authParam,
    const WidgetParam &widgetParam)
{
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP) &&
        (widgetParam.windowMode != WindowModeType::UNKNOWN_WINDOW_MODE)) {
        IAM_LOGE("normal app can't set window mode.");
        return INVALID_PARAMETERS;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("CheckPermission failed");
        return CHECK_PERMISSION_FAILED;
    }
    int32_t ret = CheckAuthWidgetType(authParam.authType);
    if (ret != SUCCESS) {
        IAM_LOGE("CheckAuthWidgetType fail.");
        return ret;
    }
    if (!CheckAuthTrustLevel(authParam.authTrustLevel)) {
        IAM_LOGE("authTrustLevel is not in correct range");
        return ResultCode::TRUST_LEVEL_NOT_SUPPORT;
    }
    static const size_t authTypeTwo = 2;
    static const size_t authType0 = 0;
    static const size_t authType1 = 1;
    std::vector<AuthType> authType = authParam.authType;
    if (((authType.size() == authTypeTwo) &&
            (authType[authType0] == AuthType::FACE) && (authType[authType1] == AuthType::FINGERPRINT)) ||
        ((authType.size() == authTypeTwo) &&
            (authType[authType0] == AuthType::FINGERPRINT) && (authType[authType1] == AuthType::FACE))) {
        IAM_LOGE("only face and finger not support");
        return INVALID_PARAMETERS;
    }
    if (widgetParam.title.empty()) {
        IAM_LOGE("title is empty");
        return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

uint64_t UserAuthService::StartWidgetContext(const std::shared_ptr<ContextCallback> &contextCallback,
    const AuthParam &authParam, const WidgetParam &widgetParam, std::vector<AuthType> &validType,
    ContextFactory::AuthWidgetContextPara &para)
{
    Attributes extraInfo;
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    if (!AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para)) {
        IAM_LOGE("init widgetContext failed");
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    auto context = ContextFactory::CreateWidgetContext(para, contextCallback);
    if (context == nullptr || !Insert2ContextPool(context)) {
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));
    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("start widget context fail %{public}d", errorCode);
        contextCallback->OnResult(errorCode, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

int32_t UserAuthService::CheckValidSolution(int32_t userId, const AuthParam &authParam,
    const WidgetParam &widgetParam, std::vector<AuthType> &validType)
{
    int32_t ret = AuthWidgetHelper::CheckValidSolution(
        userId, authParam.authType, authParam.authTrustLevel, validType);
    if (ret != SUCCESS) {
        IAM_LOGE("CheckValidSolution fail %{public}d", ret);
        return ret;
    }
    if (!widgetParam.navigationButtonText.empty() && !CheckSingeFaceOrFinger(validType)) {
        IAM_LOGE("navigationButtonText check fail, validType.size:%{public}zu", validType.size());
        return INVALID_PARAMETERS;
    }
    if (widgetParam.windowMode == FULLSCREEN && CheckSingeFaceOrFinger(validType)) {
        IAM_LOGE("Single fingerprint or single face does not support full screen");
        return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

int32_t UserAuthService::GetCallerNameAndUserId(ContextFactory::AuthWidgetContextPara &para,
    std::shared_ptr<ContextCallback> &contextCallback)
{
    bool isBundleName = false;
    std::string callerName = "";
    int32_t callerType = 0;
    static_cast<void>(IpcCommon::GetCallerName(*this, isBundleName, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    para.callerType = callerType;
    if (isBundleName) {
        para.callingBundleName = callerName;
        para.callerName = "B_" + callerName;
    } else {
        para.callerName = "N_" + callerName;
    }
    int32_t userId;
    Attributes extraInfo;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceUserId(userId);
    para.userId = userId;
    return SUCCESS;
}

uint64_t UserAuthService::AuthWidget(int32_t apiVersion, const AuthParam &authParam,
    const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start %{public}d authTrustLevel:%{public}u", apiVersion, authParam.authTrustLevel);
    auto contextCallback = GetAuthContextCallback(apiVersion, authParam, widgetParam, callback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return BAD_CONTEXT_ID;
    }
    ContextFactory::AuthWidgetContextPara para;
    para.sdkVersion = apiVersion;
    Attributes extraInfo;
    int32_t checkRet = GetCallerNameAndUserId(para, contextCallback);
    if (checkRet != SUCCESS) {
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }
    checkRet = CheckAuthPermissionAndParam(para.userId, authParam, widgetParam);
    if (checkRet != SUCCESS) {
        IAM_LOGE("check auth widget param failed");
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }

    if (AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo) == SUCCESS) {
        IAM_LOGE("check reuse unlock result success");
        contextCallback->OnResult(SUCCESS, extraInfo);
        return REUSE_AUTH_RESULT_CONTEXT_ID;
    }
    std::vector<AuthType> validType;
    checkRet = CheckValidSolution(para.userId, authParam, widgetParam, validType);
    if (checkRet != SUCCESS) {
        IAM_LOGE("check valid solution failed");
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return StartWidgetContext(contextCallback, authParam, widgetParam, validType, para);
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

std::shared_ptr<ContextCallback> UserAuthService::GetAuthContextCallback(int32_t apiVersion,
    const AuthParam &authParam, const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return nullptr;
    }
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_AUTH_USER_BEHAVIOR);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        Attributes extraInfo;
        callback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return nullptr;
    }
    contextCallback->SetTraceSdkVersion(apiVersion);
    contextCallback->SetTraceAuthTrustLevel(authParam.authTrustLevel);

    uint32_t authWidgetType = 0;
    for (const auto authType : authParam.authType) {
        authWidgetType |= static_cast<uint32_t>(authType);
    }
    static const uint32_t bitWindowMode = 0x40000000;
    if (widgetParam.windowMode == FULLSCREEN) {
        authWidgetType |= bitWindowMode;
    }
    static const uint32_t bitNavigation = 0x80000000;
    if (!widgetParam.navigationButtonText.empty()) {
        authWidgetType |= bitNavigation;
    }
    IAM_LOGI("SetTraceAuthWidgetType %{public}08x", authWidgetType);
    contextCallback->SetTraceAuthWidgetType(authWidgetType);
    uint32_t traceReuseMode = 0;
    uint64_t traceReuseDuration = 0;
    if (authParam.reuseUnlockResult.isReuse) {
        traceReuseMode = authParam.reuseUnlockResult.reuseMode;
        traceReuseDuration = authParam.reuseUnlockResult.reuseDuration;
    }
    contextCallback->SetTraceReuseUnlockResultMode(traceReuseMode);
    contextCallback->SetTraceReuseUnlockResultDuration(traceReuseDuration);
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
        IAM_LOGE("CheckPermission failed, no permission");
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

int32_t UserAuthService::GetEnrolledState(int32_t apiVersion, AuthType authType,
    EnrolledState &enrolledState)
{
    IAM_LOGI("start");

    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    if (apiVersion < API_VERSION_12 ||
        !SystemParamManager::GetInstance().IsAuthTypeEnable(authType)) {
        IAM_LOGE("failed to check apiVersion");
        return TYPE_NOT_SUPPORT;
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
    HdiEnrolledState hdiEnrolledState = {};
    int32_t result = hdi->GetEnrolledState(userId, static_cast<HdiAuthType>(authType), hdiEnrolledState);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get enrolled state,userId:%{public}d authType:%{public}d", userId, authType);
        return result;
    }
    enrolledState.credentialDigest = hdiEnrolledState.credentialDigest;
    enrolledState.credentialCount = hdiEnrolledState.credentialCount;
    return SUCCESS;
}

bool UserAuthService::CheckAuthTypeIsValid(std::vector<AuthType> authType)
{
    if (authType.empty()) {
        return false;
    }
    for (const auto &iter : authType) {
        if (iter != AuthType::PIN && iter != AuthType::FACE && iter != AuthType::FINGERPRINT) {
            return false;
        }
    }
    return true;
}

int32_t UserAuthService::RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
    const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGE("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    if (!CheckAuthTypeIsValid(authType)) {
        IAM_LOGE("failed to check authType");
        return INVALID_PARAMETERS;
    }

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    int32_t result = AuthEventListenerManager::GetInstance().RegistUserAuthSuccessEventListener(authType, listener);
    if (result != SUCCESS) {
        IAM_LOGE("failed to regist auth event listener");
        return result;
    }

    return SUCCESS;
}

int32_t UserAuthService::UnRegistUserAuthSuccessEventListener(
    const sptr<AuthEventListenerInterface> &listener)
{
    IAM_LOGE("start");
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, INVALID_PARAMETERS);

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    int32_t result = AuthEventListenerManager::GetInstance().UnRegistUserAuthSuccessEventListener(listener);
    if (result != SUCCESS) {
        IAM_LOGE("failed to unregist auth event listener");
        return result;
    }

    return SUCCESS;
}

int32_t UserAuthService::SetGlobalConfigParam(const GlobalConfigParam &param)
{
    IAM_LOGE("start");
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }
    int32_t result = hdi->SetGlobalConfigParam(param);
    if (result != SUCCESS) {
        IAM_LOGE("failed to Set global config param");
        return result;
    }
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS