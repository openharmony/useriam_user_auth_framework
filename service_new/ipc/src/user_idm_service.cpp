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

#include "user_idm_service.h"
#include "accesstoken_kit.h"

#include "context_factory.h"
#include "context_helper.h"
#include "context_pool.h"
#include "hdi_wrapper.h"
#include "iam_logger.h"
#include "ipc_common.h"
#include "resource_node_pool.h"
#include "resource_node_utils.h"
#include "result_code.h"
#include "user_idm_callback_proxy.h"
#include "user_idm_database.h"
#include "user_idm_session_controller.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
    const std::string MANAGE_USER_IDM_PERMISSION = "ohos.permission.MANAGE_USER_IDM";
    const std::string USE_USER_IDM_PERMISSION = "ohos.permission.USE_USER_IDM";
} // namespace

REGISTER_SYSTEM_ABILITY_BY_ID(UserIdmService, SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);

UserIdmService::UserIdmService(int32_t systemAbilityId, bool runOnCreate) : SystemAbility(systemAbilityId, runOnCreate)
{
}

void UserIdmService::OnStart()
{
    IAM_LOGI("start service");
    if (!Publish(this)) {
        IAM_LOGE("failed to publish service");
    }
}

void UserIdmService::OnStop()
{
    IAM_LOGI("stop service");
}

int32_t UserIdmService::OpenSession(std::optional<int32_t> userId, std::vector<uint8_t> &challenge)
{
    IAM_LOGI("start");
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        return INVALID_PARAMETERS;
    }
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    auto contextList = ContextPool::Instance().Select(CONTEXT_ENROLL);
    for (const auto &context : contextList) {
        if (auto ctx = context.lock(); ctx != nullptr) {
            IAM_LOGE("force stop the old context ****%{public}hx", static_cast<uint16_t>(ctx->GetContextId()));
            ctx->Stop();
            ContextPool::Instance().Delete(ctx->GetContextId());
        }
    }

    if (!UserIdmSessionController::Instance().OpenSession(userId.value(), challenge)) {
        IAM_LOGE("failed to open session");
        return FAIL;
    }

    return SUCCESS;
}

void UserIdmService::CloseSession(std::optional<int32_t> userId)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return;
    }
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        return;
    }

    if (!UserIdmSessionController::Instance().CloseSession(userId.value())) {
        IAM_LOGE("failed to get close session");
    }
}

int32_t UserIdmService::GetCredentialInfo(std::optional<int32_t> userId, AuthType authType,
    const sptr<IdmGetCredentialInfoCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        return INVALID_PARAMETERS;
    }
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    auto credInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId.value(), authType);

    std::optional<PinSubType> pinSubType = std::nullopt;
    auto userInfo = UserIdmDatabase::Instance().GetSecUserInfo(userId.value());
    if (userInfo == nullptr) {
        IAM_LOGE("failed to get userInfo");
        return INVALID_PARAMETERS;
    }

    pinSubType = userInfo->GetPinSubType();
    IAM_LOGE("before OnCredentialInfos");
    callback->OnCredentialInfos(credInfos, pinSubType);

    return SUCCESS;
}

int32_t UserIdmService::GetSecInfo(std::optional<int32_t> userId, const sptr<IdmGetSecureUserInfoCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        return INVALID_PARAMETERS;
    }

    auto userInfos = UserIdmDatabase::Instance().GetSecUserInfo(userId.value());
    if (userInfos == nullptr) {
        IAM_LOGE("current userid %{public}d is not existed", userId.value());
        return INVALID_PARAMETERS;
    }
    callback->OnSecureUserInfo(userInfos);

    return SUCCESS;
}

void UserIdmService::AddCredential(std::optional<int32_t> userId, AuthType authType, PinSubType pinSubType,
    const std::vector<uint8_t> &token, const sptr<IdmCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    Attributes extraInfo;

    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        callback->OnResult(INVALID_PARAMETERS, extraInfo);
        return;
    }

    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        callback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return;
    }

    uint64_t callingUid = static_cast<uint64_t>(this->GetCallingUid());
    auto context =
        ContextFactory::CreateEnrollContext(userId.value(), authType, pinSubType, token, callingUid, callback);
    if (!ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        callback->OnResult(FAIL, extraInfo);
        return;
    }

    auto cleaner = ContextHelper::Cleaner(context);
    context->SetContextStopCallback(cleaner);

    if (!context->Start()) {
        IAM_LOGE("failed to start enroll");
        callback->OnResult(FAIL, extraInfo);
        cleaner();
    }
}

void UserIdmService::UpdateCredential(std::optional<int32_t> userId, AuthType authType, PinSubType pinSubType,
    const std::vector<uint8_t> &token, const sptr<IdmCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    if (token.empty()) {
        IAM_LOGE("token is empty in update");
        return;
    }
    Attributes extraInfo;
    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        callback->OnResult(FAIL, extraInfo);
        return;
    }

    auto credInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId.value(), authType);
    if (credInfos.empty()) {
        IAM_LOGE("current userid %{public}d has no credential for type %{public}u", userId.value(), authType);
        callback->OnResult(FAIL, extraInfo);
        return;
    }

    AddCredential(userId, authType, pinSubType, token, callback);
}

int32_t UserIdmService::Cancel(std::optional<int32_t> userId, const std::optional<std::vector<uint8_t>> &challenge)
{
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    auto context = ContextPool::Instance().Select(contextId_).lock();
    if (context == nullptr || !context->Stop()) {
        IAM_LOGE("failed to cancel");
        return FAIL;
    }

    if (!ContextPool::Instance().Delete(contextId_)) {
        IAM_LOGE("failed to delete context");
        return FAIL;
    }

    return SUCCESS;
}

int32_t UserIdmService::EnforceDelUser(int32_t userId, const sptr<IdmCallback> &callback)
{
    IAM_LOGI("to delete userid: %{public}d", userId);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }
    Attributes extraInfo;

    auto userInfo = UserIdmDatabase::Instance().GetSecUserInfo(userId);
    if (userInfo == nullptr) {
        IAM_LOGE("current userid %{public}d is not existed", userId);
        callback->OnResult(INVALID_PARAMETERS, extraInfo);
        return INVALID_PARAMETERS;
    }

    std::vector<std::shared_ptr<CredentialInfo>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().DeleteUserEnforce(userId, credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to enforce delete user");
        static_cast<void>(extraInfo.SetUint64Value(Attributes::ATTR_CREDENTIAL_ID, 0));
        callback->OnResult(ret, extraInfo);
        return ret;
    }

    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
    }

    IAM_LOGI("delete user success");
    callback->OnResult(SUCCESS, extraInfo);
    return SUCCESS;
}

void UserIdmService::DelUser(std::optional<int32_t> userId, const std::vector<uint8_t> authToken,
    const sptr<IdmCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    Attributes extraInfo;
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        callback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return;
    }

    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        callback->OnResult(INVALID_PARAMETERS, extraInfo);
        return;
    }

    if (authToken.empty()) {
        IAM_LOGE("token is empty in delete");
        return;
    }

    std::vector<std::shared_ptr<CredentialInfo>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().DeleteUser(userId.value(), authToken, credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete user");
        callback->OnResult(ret, extraInfo);
        return;
    }

    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
    }
    IAM_LOGI("delete user end");

    callback->OnResult(ret, extraInfo);
}

void UserIdmService::DelCredential(std::optional<int32_t> userId, uint64_t credentialId,
    const std::vector<uint8_t> &authToken, const sptr<IdmCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    Attributes extraInfo;
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        callback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return;
    }

    if (IpcCommon::GetCallingUserId(*this, userId) != SUCCESS) {
        IAM_LOGE("failed to get userId");
        callback->OnResult(INVALID_PARAMETERS, extraInfo);
        return;
    }

    std::shared_ptr<CredentialInfo> oldInfo;
    auto ret = UserIdmDatabase::Instance().DeleteCredentialInfo(userId.value(), credentialId, authToken, oldInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete CredentialInfo");
        callback->OnResult(ret, extraInfo);
        return;
    }

    IAM_LOGI("delete credentialInfo success");
    std::vector<std::shared_ptr<CredentialInfo>> list = {oldInfo};
    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(list);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
    }

    callback->OnResult(ret, extraInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS