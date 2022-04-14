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

#include "userauth_service.h"

#include "accesstoken_kit.h"
#include "os_account_manager.h"

#include "thread_groups.h"
#include "userauth_hilog_wrapper.h"
#include "useriam_common.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using namespace OHOS::UserIAM::Utils;

const static int AUTH_TRUST_LEVEL_SYS = 1;
const static std::string GROUP_AUTH = "GROUP_AUTH";
static const std::string ACCESS_USER_AUTH_INTERNAL_PERMISSION = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
static const std::string ACCESS_BIOMETRIC_PERMISSION = "ohos.permission.ACCESS_BIOMETRIC";

REGISTER_SYSTEM_ABILITY_BY_ID(UserAuthService, SUBSYS_USERIAM_SYS_ABILITY_USERAUTH, true);

UserAuthService::UserAuthService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
}

UserAuthService::~UserAuthService() = default;

void UserAuthService::OnStart()
{
    USERAUTH_HILOGI(MODULE_SERVICE, "Start service");
    if (!Publish(this)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to publish service");
    }

    IamThreadGroups::GetInstance()->CreateThreadGroup(GROUP_AUTH);

    bool ret = OHOS::UserIAM::Common::IsIAMInited();
    if (!ret) {
        OHOS::UserIAM::Common::Init();
    }
}

void UserAuthService::OnStop()
{
    USERAUTH_HILOGI(MODULE_SERVICE, "Stop service");
    IamThreadGroups::GetInstance()->DestroyThreadGroup(GROUP_AUTH);
    bool init = OHOS::UserIAM::Common::IsIAMInited();
    if (!init) {
        return;
    }
    int32_t ret = OHOS::UserIAM::Common::Close();
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to Stop service");
    }
}

bool UserAuthService::CheckPermission(const std::string &permission)
{
    using namespace Security::AccessToken;
    uint32_t tokenId = this->GetFirstTokenID();
    if (tokenId == 0) {
        tokenId = this->GetCallingTokenID();
    }
    return AccessTokenKit::VerifyAccessToken(tokenId, permission) == RET_SUCCESS;
}

int32_t UserAuthService::GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthService GetAvailableStatus start");
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        (authType == PIN || !CheckPermission(ACCESS_BIOMETRIC_PERMISSION))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Permission check failed");
        return E_CHECK_PERMISSION_FAILED;
    }
    int32_t userId = 0;
    uint32_t authTrustLevelFromSys = AUTH_TRUST_LEVEL_SYS;
    if (authTrustLevel > ATL4 || authTrustLevel < ATL1) {
        USERAUTH_HILOGE(MODULE_SERVICE, "authTrustLevel not right");
        return TRUST_LEVEL_NOT_SUPPORT;
    }

    int32_t ret = this->GetCallingUserId(userId);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GetCallingUserId failed");
        return ret;
    }

    ret = userAuthController_.GetAuthTrustLevel(userId, authType, authTrustLevelFromSys);
    if (ret == SUCCESS) {
        USERAUTH_HILOGD(MODULE_SERVICE, "authTrustLevelFromSys:%{public}u, authTrustLevel:%{public}u",
            authTrustLevelFromSys, authTrustLevel);
        if (authTrustLevelFromSys < authTrustLevel) {
            USERAUTH_HILOGE(MODULE_SERVICE, "authTrustLevel not support");
            return TRUST_LEVEL_NOT_SUPPORT;
        }
    }

    return ret;
}

void UserAuthService::GetProperty(const GetPropertyRequest request, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthService GetProperty start");
    std::string callerName;
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Permission check failed");
        AuthResult extraInfo;
        callback->onResult(E_CHECK_PERMISSION_FAILED, extraInfo);
        return;
    }
    std::vector<int32_t> ids;
    ErrCode queryRet = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (queryRet != ERR_OK || ids.empty()) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Query active account error:%{public}zu", ids.size());
        AuthResult extraInfo;
        callback->onResult(FAIL, extraInfo);
        return;
    }

    sptr<IRemoteObject::DeathRecipient> dr = new (std::nothrow) UserAuthServiceCallbackDeathRecipient(callback);
    if ((dr == nullptr) || (!callback->AsObject()->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient UserAuthServiceCallbackDeathRecipient");
    }

    uint64_t callerId = static_cast<uint64_t>(this->GetCallingUid());
    callerName = std::to_string(callerId);
    const size_t firstAccountIndex = 0;
    USERAUTH_HILOGI(MODULE_SERVICE, "Query active account %{public}d", ids[firstAccountIndex]);
    userAuthController_.GetPropAuthInfo(ids[firstAccountIndex], callerName, callerId, request, callback);
}

void UserAuthService::SetProperty(const SetPropertyRequest request, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthService SetProperty start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Permission check failed");
        AuthResult extraInfo = {};
        callback->onResult(E_CHECK_PERMISSION_FAILED, extraInfo);
        return;
    }

    sptr<IRemoteObject::DeathRecipient> dr = new (std::nothrow) UserAuthServiceCallbackDeathRecipient(callback);
    if ((dr == nullptr) || (!callback->AsObject()->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient UserAuthServiceCallbackDeathRecipient");
    }

    uint64_t callerId = static_cast<uint64_t>(this->GetCallingUid());
    std::string callerName = std::to_string(callerId);

    int32_t ret = userAuthController_.SetExecutorProp(callerId, callerName, request, callback);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "SetExecutorProp failed");
        callback->onSetExecutorProperty(ret);
        return;
    }
}

int32_t UserAuthService::GetCallingUserId(int32_t &userId)
{
    uint32_t tokenId = this->GetFirstTokenID();
    if (tokenId == 0) {
        tokenId = this->GetCallingTokenID();
    }
    Security::AccessToken::ATokenTypeEnum callingType = Security::AccessToken::
        AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType != Security::AccessToken::TOKEN_HAP) {
        USERAUTH_HILOGE(MODULE_SERVICE, "CallingType is not hap");
        return TYPE_NOT_SUPPORT;
    }
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    int result = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Get hap token info failed");
        return TYPE_NOT_SUPPORT;
    }
    userId = static_cast<int32_t>(hapTokenInfo.userID);
    USERAUTH_HILOGI(MODULE_SERVICE, "GetCallingUserId is %{public}d", userId);
    return SUCCESS;
}

static AuthSolution GetSolutionParam(uint64_t contextId, int32_t userId, uint64_t challenge, uint32_t authType,
    uint32_t authTrustLevel)
{
    AuthSolution authSolutionParam;
    authSolutionParam.contextId = contextId;
    authSolutionParam.userId = userId;
    authSolutionParam.authTrustLevel = authTrustLevel;
    authSolutionParam.challenge = challenge;
    authSolutionParam.authType = authType;
    return authSolutionParam;
}

uint64_t UserAuthService::Auth(const uint64_t challenge, const AuthType authType, const AuthTrustLevel authTrustLevel,
    sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthService Auth start");
    const uint64_t invalidContextId = 0;
    int32_t userId = 0;
    uint64_t callerId = 0;
    std::string callerName;
    uint64_t contextId = 0;
    CoAuthInfo coAuthInfo;
    AuthResult extraInfo;

    sptr<IRemoteObject::DeathRecipient> dr = new UserAuthServiceCallbackDeathRecipient(callback);
    if ((!callback->AsObject()->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient UserAuthServiceCallbackDeathRecipient");
    }

    if (GetControllerData(callback, extraInfo, authTrustLevel, callerId, callerName, contextId) == FAIL) {
        return invalidContextId;
    }
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION) &&
        (authType == PIN || !CheckPermission(ACCESS_BIOMETRIC_PERMISSION))) {
        callback->onResult(E_CHECK_PERMISSION_FAILED, extraInfo);
        return invalidContextId;
    }
    int32_t result = this->GetCallingUserId(userId);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GetCallingUserId failed");
        callback->onResult(FAIL, extraInfo);
        return invalidContextId;
    }

    AuthSolution authSolutionParam = GetSolutionParam(contextId, userId, challenge, authType, authTrustLevel);
    result = userAuthController_.GenerateSolution(authSolutionParam, coAuthInfo.sessionIds);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GenerateSolution failed");
        callback->onResult(result, extraInfo);
        return invalidContextId;
    }

    coAuthInfo.authType = authType;
    coAuthInfo.callerID = callerId;
    coAuthInfo.contextID = contextId;
    coAuthInfo.pkgName = callerName;
    coAuthInfo.userID = userId;
    result = userAuthController_.CoAuth(coAuthInfo, callback);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "CoAuth failed");
        callback->onResult(result, extraInfo);
        return invalidContextId;
    }
    return contextId;
}

uint64_t UserAuthService::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthService AuthUser start");
    const uint64_t invalidContextId = 0;
    uint64_t callerId = 0;
    std::string callerName;
    uint64_t contextId = 0;
    AuthSolution authSolutionParam;
    CoAuthInfo coAuthInfo;
    AuthResult extraInfo = {};

    sptr<IRemoteObject::DeathRecipient> dr = new UserAuthServiceCallbackDeathRecipient(callback);
    if ((!callback->AsObject()->AddDeathRecipient(dr))) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient UserAuthServiceCallbackDeathRecipient");
    }

    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Permission check failed");
        callback->onResult(E_CHECK_PERMISSION_FAILED, extraInfo);
        return invalidContextId;
    }
    if (GetControllerData(callback, extraInfo, authTrustLevel, callerId, callerName, contextId) == FAIL) {
        return invalidContextId;
    }

    authSolutionParam.contextId = contextId;
    authSolutionParam.userId = userId;
    authSolutionParam.authTrustLevel = authTrustLevel;
    authSolutionParam.challenge = challenge;
    authSolutionParam.authType = authType;
    int32_t result = userAuthController_.GenerateSolution(authSolutionParam, coAuthInfo.sessionIds);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GenerateSolution failed");
        userAuthController_.DeleteContextId(contextId);
        callback->onResult(result, extraInfo);
        return invalidContextId;
    }

    coAuthInfo.authType = authType;
    coAuthInfo.callerID = callerId;
    coAuthInfo.contextID = contextId;
    coAuthInfo.pkgName = callerName;
    coAuthInfo.userID = userId;
    result = userAuthController_.CoAuth(coAuthInfo, callback);
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "CoAuth failed");
        userAuthController_.DeleteContextId(contextId);
        callback->onResult(result, extraInfo);
        return invalidContextId;
    }
    return contextId;
}

int32_t UserAuthService::GetControllerData(sptr<IUserAuthCallback> &callback, AuthResult &extraInfo,
    const AuthTrustLevel authTrustLevel, uint64_t &callerId, std::string &callerName, uint64_t &contextId)
{
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return FAIL;
    }
    if (ATL4 < authTrustLevel || authTrustLevel < ATL1) {
        USERAUTH_HILOGE(MODULE_SERVICE, "authTrustLevel is not right");
        callback->onResult(TRUST_LEVEL_NOT_SUPPORT, extraInfo);
        return FAIL;
    }

    callerId = static_cast<uint64_t>(this->GetCallingUid());
    callerName = std::to_string(callerId);

    if (userAuthController_.GenerateContextId(contextId) != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GenerateContextId failed");
        callback->onResult(GENERAL_ERROR, extraInfo);
        return FAIL;
    }
    if (userAuthController_.AddContextId(contextId) != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "AddContextId failed");
        callback->onResult(GENERAL_ERROR, extraInfo);
        return FAIL;
    }
    return SUCCESS;
}

int32_t UserAuthService::CancelAuth(const uint64_t contextId)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthService CancelAuth start");
    int result = INVALID_CONTEXT_ID;
    std::vector<uint64_t> sessionIds;
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION) && !CheckPermission(ACCESS_BIOMETRIC_PERMISSION)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Permission check failed");
        return E_CHECK_PERMISSION_FAILED;
    }
    int ret = userAuthController_.IsContextIdExist(contextId);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "IsContextIdExist failed");
        return result;
    }

    result = userAuthController_.CancelContext(contextId, sessionIds);
    if (result == SUCCESS) {
        for (auto const &item : sessionIds) {
            result = userAuthController_.Cancel(item);
            if (result != SUCCESS) {
                USERAUTH_HILOGE(MODULE_SERVICE, "Cancel failed");
            }
        }
        userAuthController_.DeleteContextId(contextId);
    }

    return result;
}

int32_t UserAuthService::GetVersion()
{
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthService GetVersion start");
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION) && !CheckPermission(ACCESS_BIOMETRIC_PERMISSION)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Permission check failed");
        return 0;
    }
    return userAuthController_.GetVersion();
}
UserAuthService::UserAuthServiceCallbackDeathRecipient::UserAuthServiceCallbackDeathRecipient(
    sptr<IUserAuthCallback> &impl)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthServiceCallbackDeathRecipient impl is nullptr");
        return;
    }
    callback_ = impl;
}
void UserAuthService::UserAuthServiceCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthServiceCallbackDeathRecipient OnRemoteDied failed, remote is nullptr");
        return;
    }
    callback_ = nullptr;

    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthServiceCallbackDeathRecipient Recv death notice");
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
