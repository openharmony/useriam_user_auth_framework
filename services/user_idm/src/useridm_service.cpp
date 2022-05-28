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

#include "useridm_service.h"
#include "accesstoken_kit.h"
#include "useridm_controller.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
REGISTER_SYSTEM_ABILITY_BY_ID(UserIDMService, SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);

static const std::string MANAGE_USER_IDM_PERMISSION = "ohos.permission.MANAGE_USER_IDM";
static const std::string USE_USER_IDM_PERMISSION = "ohos.permission.USE_USER_IDM";

UserIDMService::UserIDMService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
}

UserIDMService::~UserIDMService()
{
}

void UserIDMService::OnStart()
{
    USERIDM_HILOGI(MODULE_SERVICE, "Start service");
    if (!Publish(this)) {
        USERIDM_HILOGE(MODULE_SERVICE, "Failed to publish service");
    }
}

void UserIDMService::OnStop()
{
    USERIDM_HILOGI(MODULE_SERVICE, "Stop service");
}

int32_t UserIDMService::GetCallingUserId(int32_t &userId)
{
    using namespace Security::AccessToken;
    uint32_t tokenId = this->GetFirstTokenID();
    if (tokenId == 0) {
        tokenId = this->GetCallingTokenID();
    }
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType != TOKEN_HAP) {
        USERIDM_HILOGE(MODULE_SERVICE, "CallingType is not hap");
        return TYPE_NOT_SUPPORT;
    }
    HapTokenInfo hapTokenInfo;
    int result = AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
    if (result != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "Get hap token info failed");
        return TYPE_NOT_SUPPORT;
    }
    userId = static_cast<int32_t>(hapTokenInfo.userID);
    return SUCCESS;
}

bool UserIDMService::CheckPermission(const std::string &permission)
{
    using namespace Security::AccessToken;
    uint32_t tokenId = this->GetFirstTokenID();
    if (tokenId == 0) {
        tokenId = this->GetCallingTokenID();
    }
    return AccessTokenKit::VerifyAccessToken(tokenId, permission) == RET_SUCCESS;
}

uint64_t UserIDMService::OpenSession()
{
    USERIDM_HILOGD(MODULE_SERVICE, "service OpenSession start");
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        return 0;
    }

    int32_t userId = 0;
    uint64_t challenge = 0;
    int32_t ret = this->GetCallingUserId(userId);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "get userId failed");
        return 0;
    }
    USERIDM_HILOGI(MODULE_SERVICE, "OpenSession get userId: %{public}d", userId);

    UserIDMController::GetInstance().OpenEditSessionCtrl(userId, challenge);

    return challenge;
}

uint64_t UserIDMService::OpenSession(const int32_t userId)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service OpenSession start with userid: %{public}d", userId);
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        return 0;
    }
    uint64_t challenge = 0;
    UserIDMController::GetInstance().OpenEditSessionCtrl(userId, challenge);
    return challenge;
}

void UserIDMService::CloseSession()
{
    USERIDM_HILOGD(MODULE_SERVICE, "service CloseSession start");
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        return;
    }

    UserIDMController::GetInstance().CloseEditSessionCtrl();
}

void UserIDMService::CloseSession(const int32_t userId)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service CloseSession start with userid: %{public}d", userId);
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        return;
    }
    UserIDMController::GetInstance().CloseEditSessionCtrl(userId);
}

int32_t UserIDMService::GetAuthInfo(const AuthType authType, const sptr<IGetInfoCallback>& callback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service GetAuthInfo start");
    if (callback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return INVALID_PARAMETERS;
    }

    if (!CheckPermission(USE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        return CHECK_PERMISSION_FAILED;
    }

    int32_t userId = 0;
    int32_t ret = this->GetCallingUserId(userId);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "get userId failed");
        return ret;
    }
    std::vector<CredentialInfo> credInfos;
    ret = UserIDMController::GetInstance().GetAuthInfoCtrl(userId, authType, credInfos);

    callback->OnGetInfo(credInfos);

    return ret;
}

int32_t UserIDMService::GetAuthInfo(const int32_t userId, const AuthType authType,
    const sptr<IGetInfoCallback>& callback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service GetAuthInfoById start with userid: %{public}d", userId);
    if (callback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return INVALID_PARAMETERS;
    }
    std::vector<CredentialInfo> credInfos;
    int32_t ret = UserIDMController::GetInstance().GetAuthInfoCtrl(userId, authType, credInfos);
    callback->OnGetInfo(credInfos);
    return ret;
}

int32_t UserIDMService::GetSecInfo(const int32_t userId, const sptr<IGetSecInfoCallback>& callback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service GetSecInfo start with userid: %{public}d", userId);
    if (callback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return INVALID_PARAMETERS;
    }
    SecInfo secInfos = {};
    int32_t ret = UserIDMController::GetInstance().GetSecureInfoCtrl(userId,
        secInfos.secureUid, secInfos.enrolledInfo);
    if (ret != SUCCESS || secInfos.enrolledInfo.size() > UINT32_MAX) {
        USERIDM_HILOGE(MODULE_SERVICE, "GetSecureInfoCtrl failed");
        callback->OnGetSecInfo(secInfos);
        return FAIL;
    }
    secInfos.enrolledInfoLen = secInfos.enrolledInfo.size();
    USERIDM_HILOGI(MODULE_SERVICE, "SecInfo enrolledInfoLen is %{public}u", secInfos.enrolledInfoLen);
    callback->OnGetSecInfo(secInfos);
    return SUCCESS;
}

void UserIDMService::AddCredential(const AddCredInfo& credInfo, const sptr<IIDMCallback>& callback)
{
    USERIDM_HILOGI(MODULE_SERVICE, "service AddCredential start");
    if (callback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }

    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        RequestResult reqRet;
        callback->OnResult(CHECK_PERMISSION_FAILED, reqRet);
        return;
    }
    uint64_t callerId = static_cast<uint64_t>(this->GetCallingUid());

    int32_t userId = 0;
    int32_t ret = this->GetCallingUserId(userId);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "GetCallingUserId failed");
        RequestResult reqRet;
        callback->OnResult(ret, reqRet);
        return;
    }
    UserIDMController::GetInstance().AddCredentialCtrl(userId, callerId, credInfo, callback);
}

void UserIDMService::AddCredential(const int32_t userId, const AddCredInfo& credInfo,
    const sptr<IIDMCallback>& innerkitsCallback)
{
    USERIDM_HILOGI(MODULE_SERVICE, "service AddCredential start with userid: %{public}d", userId);
    if (innerkitsCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "innerkitsCallback is nullptr");
        return;
    }
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(CHECK_PERMISSION_FAILED, reqRet);
        return;
    }
    uint64_t callerId = static_cast<uint64_t>(this->GetCallingUid());
    UserIDMController::GetInstance().AddCredentialCtrl(userId, callerId, credInfo, innerkitsCallback);
}

void UserIDMService::UpdateCredential(const AddCredInfo& credInfo, const sptr<IIDMCallback>& innerkitsCallback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service UpdateCredential start");
    if (innerkitsCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "innerkitsCallback is nullptr");
        return;
    }

    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(CHECK_PERMISSION_FAILED, reqRet);
        return;
    }
    uint64_t callerId = static_cast<uint64_t>(this->GetCallingUid());
    std::string callerName = std::to_string(callerId);
    int32_t userId = 0;
    int32_t ret = this->GetCallingUserId(userId);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "GetCallingUserId failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(ret, reqRet);
        return;
    }
    UserIDMController::GetInstance().UpdateCredentialCtrl(userId, callerId, callerName, credInfo, innerkitsCallback);
}

void UserIDMService::UpdateCredential(const int32_t userId, const AddCredInfo& credInfo,
    const sptr<IIDMCallback>& innerkitsCallback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service UpdateCredential start with userid: %{public}d", userId);
    if (innerkitsCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "innerkitsCallback is nullptr");
        return;
    }
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(CHECK_PERMISSION_FAILED, reqRet);
        return;
    }
    uint64_t callerId = static_cast<uint64_t>(this->GetCallingUid());
    std::string callerName = std::to_string(callerId);
    UserIDMController::GetInstance().UpdateCredentialCtrl(userId, callerId, callerName, credInfo, innerkitsCallback);
}

int32_t UserIDMService::Cancel(const uint64_t challenge)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service Cancel start");
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        return CHECK_PERMISSION_FAILED;
    }

    int32_t ret = UserIDMController::GetInstance().DelSchedleIdCtrl(challenge);

    return ret;
}

int32_t UserIDMService::Cancel(const int32_t userId)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service Cancel start with userid: %{public}d", userId);
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        return CHECK_PERMISSION_FAILED;
    }
    return UserIDMController::GetInstance().DelSchedleIdCtrl(userId);
}

int32_t UserIDMService::EnforceDelUser(const int32_t userId, const sptr<IIDMCallback>& callback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service EnforceDelUser start with userid: %{public}d", userId);
    if (callback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return INVALID_PARAMETERS;
    }
    std::vector<CredentialInfo> credInfos;
    int32_t ret = UserIDMController::GetInstance().DeleteUserByForceCtrl(userId, credInfos);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "DeleteUserByForceCtrl return fail");
        RequestResult reqRet;
        reqRet.credentialId = 0;
        callback->OnResult(ret, reqRet);
    } else {
        ret = UserIDMController::GetInstance().DelExecutorPinInfoCtrl(callback, credInfos);
    }
    return ret;
}

void UserIDMService::DelUser(const std::vector<uint8_t> authToken, const sptr<IIDMCallback>& callback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service DelUser start");
    if (callback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }

    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        RequestResult reqRet;
        callback->OnResult(CHECK_PERMISSION_FAILED, reqRet);
        return;
    }

    int32_t userId = 0;
    int32_t ret =  this->GetCallingUserId(userId);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "GetCallingUserId failed");
        RequestResult reqRet;
        callback->OnResult(ret, reqRet);
        return;
    }
    std::vector<CredentialInfo> credInfos;

    ret = UserIDMController::GetInstance().DeleteUserCtrl(userId, authToken, credInfos);
    if (ret == SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "DeleteUserCtrl success");
        UserIDMController::GetInstance().DelExecutorPinInfoCtrl(callback, credInfos);
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "DeleteUserCtrl failed");
        RequestResult reqRet;
        callback->OnResult(ret, reqRet);
    }
}

void UserIDMService::DelUser(const int32_t userId, const std::vector<uint8_t> authToken,
    const sptr<IIDMCallback>& callback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service DelUser start with userid: %{public}d", userId);
    if (callback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        RequestResult reqRet;
        callback->OnResult(CHECK_PERMISSION_FAILED, reqRet);
        return;
    }
    std::vector<CredentialInfo> credInfos;
    int32_t ret = UserIDMController::GetInstance().DeleteUserCtrl(userId, authToken, credInfos);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "DeleteUserCtrl failed");
        RequestResult reqRet;
        callback->OnResult(ret, reqRet);
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "DeleteUserCtrl success");
        UserIDMController::GetInstance().DelExecutorPinInfoCtrl(callback, credInfos);
    }
}

void UserIDMService::DelCred(const uint64_t credentialId, const std::vector<uint8_t> authToken,
    const sptr<IIDMCallback>& innerkitsCallback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service DelCred start");
    if (innerkitsCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "innerkitsCallback is nullptr");
        return;
    }

    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(CHECK_PERMISSION_FAILED, reqRet);
        return;
    }

    int32_t userId = 0;
    int32_t ret = this->GetCallingUserId(userId);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "GetCallingUserId failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(ret, reqRet);
    }
    CredentialInfo credentialInfo;
    ret = UserIDMController::GetInstance().DeleteCredentialCtrl(userId, credentialId, authToken, credentialInfo);
    if (ret == SUCCESS) {
        USERIDM_HILOGI(MODULE_SERVICE, "DeleteCredentialCtrl success");

        UserIDMController::GetInstance().DelFaceCredentialCtrl(credentialInfo.authType, credentialInfo.authSubType,
            credentialInfo.credentialId, credentialInfo.templateId, innerkitsCallback);
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "DeleteCredentialCtrl failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(ret, reqRet);
    }
}

void UserIDMService::DelCredential(const int32_t userId, const uint64_t credentialId,
    const std::vector<uint8_t> authToken, const sptr<IIDMCallback>& innerkitsCallback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "service DelCredential start with userid: %{public}d", userId);
    if (innerkitsCallback == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "innerkitsCallback is nullptr");
        return;
    }
    if (!CheckPermission(MANAGE_USER_IDM_PERMISSION)) {
        USERIDM_HILOGE(MODULE_SERVICE, "check permission failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(CHECK_PERMISSION_FAILED, reqRet);
        return;
    }
    CredentialInfo credentialInfo;
    int32_t ret = UserIDMController::GetInstance().DeleteCredentialCtrl(userId, credentialId, authToken,
        credentialInfo);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "DeleteCredentialCtrl failed");
        RequestResult reqRet;
        innerkitsCallback->OnResult(ret, reqRet);
    } else {
        USERIDM_HILOGI(MODULE_SERVICE, "DeleteCredentialCtrl success");
        UserIDMController::GetInstance().DelFaceCredentialCtrl(credentialInfo.authType, credentialInfo.authSubType,
            credentialInfo.credentialId, credentialInfo.templateId, innerkitsCallback);
    }
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
