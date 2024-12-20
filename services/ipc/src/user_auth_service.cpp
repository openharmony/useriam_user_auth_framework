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
#include "context_helper.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "iam_time.h"
#include "ipc_common.h"
#include "ipc_skeleton.h"
#include "keyguard_status_listener.h"
#include "soft_bus_manager.h"
#include "widget_client.h"
#include "remote_msg_util.h"
#include "remote_iam_callback.h"
#include "remote_auth_service.h"
#include "device_manager_util.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const int32_t MINIMUM_VERSION = 0;
const int32_t CURRENT_VERSION = 1;
const int32_t USERIAM_IPC_THREAD_NUM = 4;
const uint32_t NETWORK_ID_LENGTH = 64;
const bool REMOTE_AUTH_SERVICE_RESULT = RemoteAuthService::GetInstance().Start();
int32_t GetTemplatesByAuthType(int32_t userId, AuthType authType, std::vector<uint64_t> &templateIds)
{
    templateIds.clear();
    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType, credentialInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
            userId, authType);
        return GENERAL_ERROR;
    }

    if (credentialInfos.empty()) {
        IAM_LOGE("user %{public}d has no credential type %{public}d", userId, authType);
        return SUCCESS;
    }
    
    templateIds.reserve(credentialInfos.size());
    for (auto &info : credentialInfos) {
        if (info == nullptr) {
            IAM_LOGE("info is nullptr");
            continue;
        }
        templateIds.push_back(info->GetTemplateId());
    }

    return SUCCESS;
}

bool IsTemplateIdListRequired(const std::vector<Attributes::AttributeKey> &keys)
{
    for (const auto &key : keys) {
        if (key == Attributes::AttributeKey::ATTR_PIN_SUB_TYPE ||
            key == Attributes::AttributeKey::ATTR_REMAIN_TIMES ||
            key == Attributes::AttributeKey::ATTR_FREEZING_TIME ||
            key == Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION) {
            return true;
        }
    }
    return false;
}

void GetResourceNodeByTypeAndRole(AuthType authType, ExecutorRole role,
    std::vector<std::weak_ptr<ResourceNode>> &authTypeNodes)
{
    authTypeNodes.clear();
    ResourceNodePool::Instance().Enumerate(
        [&authTypeNodes, role, authType](const std::weak_ptr<ResourceNode> &weakNode) {
            auto node = weakNode.lock();
            if (node == nullptr) {
                return;
            }
            if (node->GetAuthType() != authType) {
                return;
            }
            if (node->GetExecutorRole() != role) {
                return;
            }
            authTypeNodes.push_back(node);
        });
}

std::string GetAuthParamStr(const AuthParamInner &authParam, std::optional<RemoteAuthParam> &remoteAuthParam)
{
    std::ostringstream authParamString;
    authParamString << "userId:" << authParam.userId << " authType:" << authParam.authType
                    << " atl:" << authParam.authTrustLevel;
    if (remoteAuthParam.has_value()) {
        const uint32_t NETWORK_ID_PRINT_LEN = 4;
        const uint32_t TOKEN_ID_MIN_LEN = 2;
        auto verifierNetworkIdStr = remoteAuthParam->verifierNetworkId.value_or("").substr(0, NETWORK_ID_PRINT_LEN);
        auto collectorNetworkIdStr = remoteAuthParam->collectorNetworkId.value_or("").substr(0, NETWORK_ID_PRINT_LEN);
        auto tokenIdStr = std::to_string(remoteAuthParam->collectorTokenId.value_or(0));
        if (tokenIdStr.size() > TOKEN_ID_MIN_LEN) {
            tokenIdStr = std::string(1, tokenIdStr[0]) + "****" + std::string(1, tokenIdStr[tokenIdStr.size() - 1]);
        } else {
            tokenIdStr = "";
        }

        authParamString << " isRemoteAuth:true" << " verifierNetworkId:" << verifierNetworkIdStr << "****"
            " collectorNetworkId:" << collectorNetworkIdStr << "****" << " collectorTokenId:" << tokenIdStr;
    }
    return authParamString.str();
}
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(UserAuthService::GetInstance().get());
} // namespace
std::mutex UserAuthService::mutex_;
std::shared_ptr<UserAuthService> UserAuthService::instance_ = nullptr;

std::shared_ptr<UserAuthService> UserAuthService::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (instance_ == nullptr) {
            instance_ = Common::MakeShared<UserAuthService>();
            if (instance_ == nullptr) {
                IAM_LOGE("make share failed");
            }
        }
    }
    return instance_;
}

UserAuthService::UserAuthService()
    : SystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERAUTH, true)
{}

void UserAuthService::OnStart()
{
    IAM_LOGI("start service");
    IPCSkeleton::SetMaxWorkThreadNum(USERIAM_IPC_THREAD_NUM);
    if (!Publish(this)) {
        IAM_LOGE("failed to publish service");
    }
    SoftBusManager::GetInstance().Start();
    KeyguardStatusListenerManager::GetInstance().RegisterCommonEventListener();
}

void UserAuthService::OnStop()
{
    IAM_LOGI("stop service");
    SoftBusManager::GetInstance().Stop();
    KeyguardStatusListenerManager::GetInstance().UnRegisterCommonEventListener();
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

int32_t UserAuthService::GetAvailableStatus(int32_t apiVersion, int32_t userId, AuthType authType,
    AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start with userId");

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    return GetAvailableStatusInner(apiVersion, userId, authType, authTrustLevel);
}

int32_t UserAuthService::GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel)
{
    IAM_LOGI("start without userId");

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (apiVersion <= API_VERSION_8 && authType == PIN) {
        IAM_LOGE("authType not support");
        return TYPE_NOT_SUPPORT;
    }
    int32_t userId = INVALID_USER_ID;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        return GENERAL_ERROR;
    }
    return GetAvailableStatusInner(apiVersion, userId, authType, authTrustLevel);
}

int32_t UserAuthService::GetAvailableStatusInner(int32_t apiVersion, int32_t userId, AuthType authType,
    AuthTrustLevel authTrustLevel)
{
    if (!CheckAuthTrustLevel(authTrustLevel)) {
        IAM_LOGE("authTrustLevel is not in correct range");
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }
    int32_t checkRet = GENERAL_ERROR;
    int32_t result = hdi->GetAvailableStatus(userId, authType, authTrustLevel, checkRet);
    if (result != SUCCESS) {
        IAM_LOGE("hdi GetAvailableStatus failed");
        return GENERAL_ERROR;
    }
    IAM_LOGI("GetAvailableStatus result:%{public}d", checkRet);
    return checkRet;
}

void UserAuthService::FillGetPropertyKeys(AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
    std::vector<uint32_t> &uint32Keys)
{
    uint32Keys.reserve(keys.size());
    for (const auto &key : keys) {
        if (key == Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION && authType != PIN) {
            continue;
        }
        uint32Keys.push_back(static_cast<uint32_t>(key));
    }
}

void UserAuthService::FillGetPropertyValue(AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
    Attributes &values)
{
    for (const auto &key : keys) {
        if (key == Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION && authType != PIN) {
            if (!values.SetInt32Value(Attributes::ATTR_NEXT_FAIL_LOCKOUT_DURATION, FIRST_LOCKOUT_DURATION_EXCEPT_PIN)) {
                IAM_LOGE("set nextFailLockoutDuration failed, authType %{public}d", authType);
            }
            break;
        }
    }
}

std::shared_ptr<ResourceNode> UserAuthService::GetResourseNode(AuthType authType)
{
    std::vector<std::weak_ptr<ResourceNode>> authTypeNodes;
    GetResourceNodeByTypeAndRole(authType, ALL_IN_ONE, authTypeNodes);
    if (authTypeNodes.size() != 1) {
        IAM_LOGE("auth type %{public}d resource node num %{public}zu is not expected",
            authType, authTypeNodes.size());
        return nullptr;
    }

    auto resourceNode = authTypeNodes[0].lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        return nullptr;
    }

    return resourceNode;
}

void UserAuthService::GetProperty(int32_t userId, AuthType authType,
    const std::vector<Attributes::AttributeKey> &keys, sptr<GetExecutorPropertyCallbackInterface> &callback)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    Attributes values;

    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        callback->OnGetExecutorPropertyResult(CHECK_PERMISSION_FAILED, values);
        return;
    }

    std::vector<uint64_t> templateIds;
    if (IsTemplateIdListRequired(keys)) {
        int32_t ret = GetTemplatesByAuthType(userId, authType, templateIds);
        if (ret != SUCCESS) {
            IAM_LOGE("get templates fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
                userId, authType);
            callback->OnGetExecutorPropertyResult(GENERAL_ERROR, values);
            return;
        }
        if (templateIds.size() == 0) {
            IAM_LOGE("template id list is required, but templateIds size is 0");
            callback->OnGetExecutorPropertyResult(NOT_ENROLLED, values);
            return;
        }
    }

    auto resourceNode = GetResourseNode(authType);
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        callback->OnGetExecutorPropertyResult(GENERAL_ERROR, values);
        return;
    }

    std::vector<uint32_t> uint32Keys;
    FillGetPropertyKeys(authType, keys, uint32Keys);
    Attributes attr;
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);
    attr.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, uint32Keys);

    int32_t result = resourceNode->GetProperty(attr, values);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get property, result = %{public}d", result);
    }
    FillGetPropertyValue(authType, keys, values);

    callback->OnGetExecutorPropertyResult(result, values);
}

void UserAuthService::SetProperty(int32_t userId, AuthType authType, const Attributes &attributes,
    sptr<SetExecutorPropertyCallbackInterface> &callback)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
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
    GetResourceNodeByTypeAndRole(authType, ALL_IN_ONE, authTypeNodes);
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
    contextCallback->SetTraceAuthWidgetType(authType);
    contextCallback->SetTraceAuthTrustLevel(authTrustLevel);
    contextCallback->SetTraceSdkVersion(apiVersion);
    return contextCallback;
}

int32_t UserAuthService::CheckAuthPermissionAndParam(int32_t authType, const int32_t &callerType,
    const std::string &callerName, AuthTrustLevel authTrustLevel)
{
    if (!IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (callerType == Security::AccessToken::TOKEN_HAP && (!IpcCommon::CheckForegroundApplication(callerName))) {
        IAM_LOGE("failed to check foreground application");
        return CHECK_PERMISSION_FAILED;
    }
    if (authType == PIN) {
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
    std::string callerName = "";
    Attributes extraInfo;
    int32_t callerType = 0;
    if ((!IpcCommon::GetCallerName(*this, callerName, callerType))) {
        IAM_LOGE("get bundle name fail");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth GetCallerName fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    int32_t checkRet = CheckAuthPermissionAndParam(authType, callerType, callerName, authTrustLevel);
    if (checkRet != SUCCESS) {
        IAM_LOGE("check auth permission and param fail");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth CheckAuthPermissionAndParam fail");
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }
    int32_t userId = INVALID_USER_ID;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth GetCallingUserId fail");
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
    para.callerName = callerName;
    para.callerType = callerType;
    para.sdkVersion = apiVersion;
    para.authIntent = AuthIntent::DEFAULT;
    para.isOsAccountVerified = IpcCommon::IsOsAccountVerified(userId);
    return StartAuthContext(apiVersion, para, contextCallback);
}

uint64_t UserAuthService::StartAuthContext(int32_t apiVersion, Authentication::AuthenticationPara para,
    const std::shared_ptr<ContextCallback> &contextCallback)
{
    Attributes extraInfo;
    auto context = ContextFactory::CreateSimpleAuthContext(para, contextCallback);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth insert context fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    contextCallback->SetTraceAuthContextId(context->GetContextId());
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));

    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("failed to start auth apiVersion:%{public}d errorCode:%{public}d", apiVersion, errorCode);
        contextCallback->SetTraceAuthFinishReason("UserAuthService Auth start context fail");
        contextCallback->OnResult(errorCode, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

uint64_t UserAuthService::StartRemoteAuthInvokerContext(AuthParamInner authParam,
    RemoteAuthInvokerContextParam &param, const std::shared_ptr<ContextCallback> &contextCallback)
{
    Attributes extraInfo;
    std::shared_ptr<Context> context = ContextFactory::CreateRemoteAuthInvokerContext(authParam, param,
        contextCallback);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->SetTraceAuthFinishReason("UserAuthService StartRemoteAuthInvokerContext insert context fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    contextCallback->SetTraceAuthContextId(context->GetContextId());

    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("failed to start auth errorCode:%{public}d", errorCode);
        contextCallback->SetTraceAuthFinishReason("UserAuthService StartRemoteAuthInvokerContext start context fail");
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
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthUser CheckAuthTrustLevel fail");
        contextCallback->OnResult(TRUST_LEVEL_NOT_SUPPORT, extraInfo);
        return false;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthUser CheckPermission fail");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return false;
    }
    return true;
}

uint64_t UserAuthService::AuthUser(AuthParamInner &authParam, std::optional<RemoteAuthParam> &remoteAuthParam,
    sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start, %{public}s", GetAuthParamStr(authParam, remoteAuthParam).c_str());
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    auto contextCallback = GetAuthContextCallback(INNER_API_VERSION_10000, authParam.challenge, authParam.authType,
        authParam.authTrustLevel, callback);
    if (contextCallback == nullptr) {
        IAM_LOGE("contextCallback is nullptr");
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceIsRemoteAuth(remoteAuthParam.has_value());
    contextCallback->SetTraceUserId(authParam.userId);
    Attributes extraInfo;
    Authentication::AuthenticationPara para = {};
    if ((!IpcCommon::GetCallerName(*this, para.callerName, para.callerType))) {
        IAM_LOGE("get caller name fail");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthUser GetCallerName fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceCallerName(para.callerName);
    contextCallback->SetTraceCallerType(para.callerType);
    if (CheckAuthPermissionAndParam(authParam.authType, authParam.authTrustLevel, contextCallback,
        extraInfo) == false) {
        return BAD_CONTEXT_ID;
    }
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.userId = authParam.userId;
    para.authType = authParam.authType;
    para.atl = authParam.authTrustLevel;
    para.challenge = authParam.challenge;
    para.endAfterFirstFail = false;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.authIntent = authParam.authIntent;
    para.isOsAccountVerified = IpcCommon::IsOsAccountVerified(authParam.userId);
    if (!remoteAuthParam.has_value()) {
        return StartAuthContext(INNER_API_VERSION_10000, para, contextCallback);
    }

    ResultCode failReason = GENERAL_ERROR;
    uint64_t contextId = AuthRemoteUser(authParam, para, remoteAuthParam.value(), contextCallback, failReason);
    if (contextId == BAD_CONTEXT_ID) {
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthRemoteUser fail");
        contextCallback->OnResult(failReason, extraInfo);
        return BAD_CONTEXT_ID;
    }

    IAM_LOGI("success");
    return contextId;
}

int32_t UserAuthService::PrepareRemoteAuthInner(const std::string &networkId)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (networkId.empty()) {
        IAM_LOGE("networkId is empty");
        return INVALID_PARAMETERS;
    }

    std::string udid;
    bool getUdidRet = DeviceManagerUtil::GetInstance().GetUdidByNetworkId(networkId, udid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUdidRet, GENERAL_ERROR);

    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, GENERAL_ERROR);

    int32_t ret = hdi->PrepareRemoteAuth(udid);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == HDF_SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

int32_t UserAuthService::PrepareRemoteAuth(const std::string &networkId, sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    int32_t ret = PrepareRemoteAuthInner(networkId);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to prepare remote auth");
    }

    Attributes attr;
    callback->OnResult(ret, attr);

    IAM_LOGI("success");
    return SUCCESS;
}

uint64_t UserAuthService::AuthRemoteUser(AuthParamInner &authParam, Authentication::AuthenticationPara &para,
    RemoteAuthParam &remoteAuthParam, const std::shared_ptr<ContextCallback> &contextCallback, ResultCode &failReason)
{
    IAM_LOGI("start");
    failReason = GENERAL_ERROR;

    if (para.authType != PIN) {
        IAM_LOGE("Remote auth only support pin auth");
        failReason = INVALID_PARAMETERS;
        return BAD_CONTEXT_ID;
    }

    if (authParam.userId == INVALID_USER_ID) {
        IAM_LOGE("userid must be set for remote auth");
        failReason = INVALID_PARAMETERS;
        return BAD_CONTEXT_ID;
    }

    std::string localNetworkId;
    bool getNetworkIdRet = DeviceManagerUtil::GetInstance().GetLocalDeviceNetWorkId(localNetworkId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getNetworkIdRet, BAD_CONTEXT_ID);

    bool completeRet = CompleteRemoteAuthParam(remoteAuthParam, localNetworkId);
    if (!completeRet) {
        IAM_LOGE("failed to complete remote auth param");
        failReason = INVALID_PARAMETERS;
        return BAD_CONTEXT_ID;
    }

    if (remoteAuthParam.collectorTokenId.has_value()) {
        para.collectorTokenId = remoteAuthParam.collectorTokenId.value();
    } else {
        para.collectorTokenId = para.tokenId;
    }

    if (remoteAuthParam.collectorNetworkId.value() == localNetworkId) {
        RemoteAuthInvokerContextParam remoteAuthInvokerContextParam;
        remoteAuthInvokerContextParam.connectionName = "";
        remoteAuthInvokerContextParam.verifierNetworkId = remoteAuthParam.verifierNetworkId.value();
        remoteAuthInvokerContextParam.collectorNetworkId = remoteAuthParam.collectorNetworkId.value();
        remoteAuthInvokerContextParam.tokenId = para.tokenId;
        remoteAuthInvokerContextParam.collectorTokenId = para.collectorTokenId;
        remoteAuthInvokerContextParam.callerName = para.callerName;
        remoteAuthInvokerContextParam.callerType = para.callerType;
        IAM_LOGI("start remote auth invoker context");
        return StartRemoteAuthInvokerContext(authParam, remoteAuthInvokerContextParam, contextCallback);
    }

    RemoteAuthContextParam remoteAuthContextParam;
    remoteAuthContextParam.authType = authParam.authType;
    remoteAuthContextParam.connectionName = "";
    remoteAuthContextParam.collectorNetworkId = remoteAuthParam.collectorNetworkId.value();
    remoteAuthContextParam.executorInfoMsg = {};
    int32_t dummyLastError = 0;
    IAM_LOGI("start remote auth context");
    return RemoteAuthService::GetInstance().StartRemoteAuthContext(
        para, remoteAuthContextParam, contextCallback, dummyLastError);
}

uint64_t UserAuthService::Identify(const std::vector<uint8_t> &challenge, AuthType authType,
    sptr<UserAuthCallbackInterface> &callback)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);

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
        IAM_LOGE("type not support %{public}d", authType);
        contextCallback->SetTraceAuthFinishReason("UserAuthService Identify IsAuthTypeEnable fail");
        contextCallback->OnResult(TYPE_NOT_SUPPORT, extraInfo);
        return BAD_CONTEXT_ID;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Identify CheckPermission fail");
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
        contextCallback->SetTraceAuthFinishReason("UserAuthService Identify insert context fail");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }

    contextCallback->SetCleaner(ContextHelper::Cleaner(context));

    if (!context->Start()) {
        IAM_LOGE("failed to start identify");
        contextCallback->SetTraceAuthFinishReason("UserAuthService Identify start context fail");
        contextCallback->OnResult(context->GetLatestError(), extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

int32_t UserAuthService::CancelAuthOrIdentify(uint64_t contextId)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
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

int32_t UserAuthService::CheckAuthPermissionAndParam(const AuthParamInner &authParam, const WidgetParam &widgetParam,
    bool isBackgroundApplication)
{
    if (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP) &&
        (widgetParam.windowMode != WindowModeType::UNKNOWN_WINDOW_MODE)) {
        IAM_LOGE("normal app can't set window mode.");
        return INVALID_PARAMETERS;
    }
    if (!authParam.isUserIdSpecified && !IpcCommon::CheckPermission(*this, ACCESS_BIOMETRIC_PERMISSION)) {
        IAM_LOGE("CheckPermission failed");
        return CHECK_PERMISSION_FAILED;
    }
    if (authParam.isUserIdSpecified && !IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("CheckPermission failed");
        return CHECK_PERMISSION_FAILED;
    }
    if (isBackgroundApplication && (!IpcCommon::CheckPermission(*this, IS_SYSTEM_APP))) {
        IAM_LOGE("failed to check foreground application");
        return CHECK_PERMISSION_FAILED;
    }
    int32_t ret = CheckAuthWidgetType(authParam.authTypes);
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
    std::vector<AuthType> authType = authParam.authTypes;
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
    const AuthParamInner &authParam, const WidgetParam &widgetParam, std::vector<AuthType> &validType,
    ContextFactory::AuthWidgetContextPara &para)
{
    Attributes extraInfo;
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.isOsAccountVerified = IpcCommon::IsOsAccountVerified(para.userId);
    if (!AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para)) {
        IAM_LOGE("init widgetContext failed");
        contextCallback->SetTraceAuthFinishReason("UserAuthService InitWidgetContextParam fail");
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    auto context = ContextFactory::CreateWidgetContext(para, contextCallback);
    if (context == nullptr || !Insert2ContextPool(context)) {
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget insert context fail");
        contextCallback->OnResult(ResultCode::GENERAL_ERROR, extraInfo);
        return BAD_CONTEXT_ID;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    contextCallback->SetCleaner(ContextHelper::Cleaner(context));
    if (!context->Start()) {
        int32_t errorCode = context->GetLatestError();
        IAM_LOGE("start widget context fail %{public}d", errorCode);
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget start context fail");
        contextCallback->OnResult(errorCode, extraInfo);
        return BAD_CONTEXT_ID;
    }
    return context->GetContextId();
}

int32_t UserAuthService::CheckValidSolution(int32_t userId, const AuthParamInner &authParam,
    const WidgetParam &widgetParam, std::vector<AuthType> &validType)
{
    int32_t ret = AuthWidgetHelper::CheckValidSolution(
        userId, authParam.authTypes, authParam.authTrustLevel, validType);
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

int32_t UserAuthService::GetCallerInfo(bool isUserIdSpecified, int32_t userId,
    ContextFactory::AuthWidgetContextPara &para, bool &isBackgroundApplication,
    std::shared_ptr<ContextCallback> &contextCallback)
{
    static_cast<void>(IpcCommon::GetCallerName(*this, para.callerName, para.callerType));
    contextCallback->SetTraceCallerName(para.callerName);
    contextCallback->SetTraceCallerType(para.callerType);
    static_cast<void>(IpcCommon::GetCallingAppID(*this, para.callingAppID));

    if (para.sdkVersion < INNER_API_VERSION_10000 && para.callerType == Security::AccessToken::TOKEN_HAP &&
        (!IpcCommon::CheckForegroundApplication(para.callerName))) {
        isBackgroundApplication = true;
    }
    contextCallback->SetTraceIsBackgroundApplication(isBackgroundApplication);

    if (isUserIdSpecified) {
        para.userId = userId;
        contextCallback->SetTraceUserId(para.userId);
        return SUCCESS;
    }
    if (IpcCommon::GetCallingUserId(*this, para.userId) != SUCCESS) {
        IAM_LOGE("get callingUserId failed");
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceUserId(para.userId);
    return SUCCESS;
}

uint64_t UserAuthService::AuthWidget(int32_t apiVersion, const AuthParamInner &authParam,
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
    bool isBackgroundApplication = false;
    int32_t checkRet = GetCallerInfo(authParam.isUserIdSpecified, authParam.userId, para, isBackgroundApplication,
        contextCallback);
    if (checkRet != SUCCESS) {
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget GetCallerInfo fail");
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }
    checkRet = CheckAuthPermissionAndParam(authParam, widgetParam, isBackgroundApplication);
    if (checkRet != SUCCESS) {
        IAM_LOGE("check permission and auth widget param failed");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget CheckAuthPermissionAndParam fail");
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }

    if (AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo) == SUCCESS) {
        IAM_LOGE("check reuse unlock result success");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget CheckReuseUnlockResult success");
        contextCallback->OnResult(SUCCESS, extraInfo);
        return REUSE_AUTH_RESULT_CONTEXT_ID;
    }
    std::vector<AuthType> validType;
    checkRet = CheckValidSolution(para.userId, authParam, widgetParam, validType);
    if (checkRet != SUCCESS && checkRet != PIN_EXPIRED) {
        IAM_LOGE("check valid solution failed");
        contextCallback->SetTraceAuthFinishReason("UserAuthService AuthWidget CheckValidSolution fail");
        contextCallback->OnResult(checkRet, extraInfo);
        return BAD_CONTEXT_ID;
    }
    if (checkRet == PIN_EXPIRED) {
        para.isPinExpired = true;
        validType.emplace_back(AuthType::PIN);
    }
    ProcessWidgetSessionExclusive();
    return StartWidgetContext(contextCallback, authParam, widgetParam, validType, para);
}

void UserAuthService::ProcessWidgetSessionExclusive()
{
    auto contextList = ContextPool::Instance().Select(ContextType::WIDGET_AUTH_CONTEXT);
    for (const auto &context : contextList) {
        if (auto ctx = context.lock(); ctx != nullptr) {
            IAM_LOGE("widget session exclusive, force stop the old context ****%{public}hx",
                static_cast<uint16_t>(ctx->GetContextId()));
            ctx->Stop();
        }
    }
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
    const AuthParamInner &authParam, const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback)
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
    for (const auto authType : authParam.authTypes) {
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
    IAM_LOGE("RegisterWidgetCallback tokenId %{public}s", GET_MASKED_STRING(tokenId).c_str());

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

    if (apiVersion < API_VERSION_12) {
        IAM_LOGE("failed to check apiVersion");
        return TYPE_NOT_SUPPORT;
    }

    int32_t userId = INVALID_USER_ID;
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
    enrolledState.credentialCount = hdiEnrolledState.credentialCount;
    enrolledState.credentialDigest = hdiEnrolledState.credentialDigest;
    if (apiVersion < INNER_API_VERSION_10000) {
        enrolledState.credentialDigest = hdiEnrolledState.credentialDigest & UINT16_MAX;
    }
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
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
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
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
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
    IAM_LOGI("start, GlobalConfigType is %{public}d, userIds size %{public}zu, authTypes size %{public}zu",
        param.type, param.userIds.size(), param.authTypes.size());
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (param.userIds.size() > MAX_USER || param.authTypes.size() > MAX_AUTH_TYPE_SIZE ||
        param.authTypes.size() == 0) {
        IAM_LOGE("bad global config param");
        return INVALID_PARAMETERS;
    }

    HdiGlobalConfigParam paramConfig = {};
    switch (param.type) {
        case GlobalConfigType::PIN_EXPIRED_PERIOD:
            if (param.authTypes.size() != 1 || param.authTypes[0] != PIN) {
                IAM_LOGE("bad authTypes for PIN_EXPIRED_PERIOD");
                return INVALID_PARAMETERS;
            }
            paramConfig.value.pinExpiredPeriod = param.value.pinExpiredPeriod;
            break;
        case GlobalConfigType::ENABLE_STATUS:
            paramConfig.value.enableStatus = param.value.enableStatus;
            break;
        default:
            IAM_LOGE("bad global config type");
            return INVALID_PARAMETERS;
    }
    paramConfig.type = static_cast<HdiGlobalConfigType>(param.type);
    paramConfig.userIds = param.userIds;
    for (const auto authType : param.authTypes) {
        paramConfig.authTypes.push_back(authType);
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }
    int32_t result = hdi->SetGlobalConfigParam(paramConfig);
    if (result != SUCCESS) {
        IAM_LOGE("failed to Set global config param");
        return result;
    }

    return SUCCESS;
}

bool UserAuthService::CompleteRemoteAuthParam(RemoteAuthParam &remoteAuthParam, const std::string &localNetworkId)
{
    IAM_LOGI("start");
    if (remoteAuthParam.verifierNetworkId.has_value() && remoteAuthParam.verifierNetworkId->size() !=
        NETWORK_ID_LENGTH) {
        IAM_LOGE("invalid verifierNetworkId size");
        return false;
    }

    if (remoteAuthParam.collectorNetworkId.has_value() && remoteAuthParam.collectorNetworkId->size() !=
        NETWORK_ID_LENGTH) {
        IAM_LOGE("invalid collectorNetworkId size");
        return false;
    }

    if (!remoteAuthParam.verifierNetworkId.has_value() && !remoteAuthParam.collectorNetworkId.has_value()) {
        IAM_LOGE("neither verifierNetworkId nor collectorNetworkId is set");
        return false;
    } else if (remoteAuthParam.verifierNetworkId.has_value() && !remoteAuthParam.collectorNetworkId.has_value()) {
        IAM_LOGI("collectorNetworkId not set, verifierNetworkId set, use local networkId as collectorNetworkId");
        remoteAuthParam.collectorNetworkId = localNetworkId;
    } else if (!remoteAuthParam.verifierNetworkId.has_value() && remoteAuthParam.collectorNetworkId.has_value()) {
        IAM_LOGI("verifierNetworkId not set, collectorNetworkId set, use local networkId as verifierNetworkId");
        remoteAuthParam.verifierNetworkId = localNetworkId;
    }

    if (remoteAuthParam.verifierNetworkId.value() != localNetworkId &&
        remoteAuthParam.collectorNetworkId.value() != localNetworkId) {
        IAM_LOGE("both verifierNetworkId and collectorNetworkId are not local networkId");
        return false;
    }

    if (remoteAuthParam.verifierNetworkId.value() == remoteAuthParam.collectorNetworkId.value()) {
        IAM_LOGE("verifierNetworkId and collectorNetworkId are the same");
        return false;
    }

    if (remoteAuthParam.verifierNetworkId == localNetworkId && !remoteAuthParam.collectorTokenId.has_value()) {
        IAM_LOGE("this device is verifier, collectorTokenId not set");
        return false;
    }

    if (remoteAuthParam.collectorNetworkId == localNetworkId && !remoteAuthParam.collectorTokenId.has_value()) {
        IAM_LOGI("this device is collector, update collectorTokenId with caller token id");
        remoteAuthParam.collectorTokenId = IpcCommon::GetAccessTokenId(*this);
    }

    IAM_LOGI("success");
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS