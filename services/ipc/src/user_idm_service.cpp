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

#include "string_ex.h"
#include "accesstoken_kit.h"

#include "context_helper.h"
#include "context_pool.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_defines.h"
#include "iam_time.h"
#include "ipc_common.h"
#include "ipc_skeleton.h"
#include "iam_common_defines.h"
#include "publish_event_adapter.h"
#include "resource_node_pool.h"
#include "resource_node_utils.h"
#include "system_param_manager.h"
#include "user_idm_callback_proxy.h"
#include "user_idm_database.h"
#include "user_idm_session_controller.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
REGISTER_SYSTEM_ABILITY_BY_ID(UserIdmService, SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);
constexpr int32_t USERIAM_IPC_THREAD_NUM = 4;

UserIdmService::UserIdmService(int32_t systemAbilityId, bool runOnCreate) : SystemAbility(systemAbilityId, runOnCreate)
{
}

void UserIdmService::OnStart()
{
    IAM_LOGI("start service");
    IPCSkeleton::SetMaxWorkThreadNum(USERIAM_IPC_THREAD_NUM);
    if (!Publish(this)) {
        IAM_LOGE("failed to publish service");
    }
}

void UserIdmService::OnStop()
{
    IAM_LOGI("stop service");
}

int32_t UserIdmService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    IAM_LOGI("start");
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

    if (!UserIdmSessionController::Instance().OpenSession(userId, challenge)) {
        IAM_LOGE("failed to open session");
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

void UserIdmService::CloseSession(int32_t userId)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return;
    }

    if (!UserIdmSessionController::Instance().CloseSession(userId)) {
        IAM_LOGE("failed to get close session");
    }
}

int32_t UserIdmService::GetCredentialInfoInner(int32_t userId, AuthType authType,
    std::vector<CredentialInfo> &credInfoList)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    auto credInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType);
    if (credInfos.empty()) {
        IAM_LOGE("no cred enrolled");
        return NOT_ENROLLED;
    }
    for (const auto &credInfo : credInfos) {
        if (credInfo == nullptr) {
            IAM_LOGE("credInfo is nullptr");
            return GENERAL_ERROR;
        }
        CredentialInfo info = {};
        info.credentialId = credInfo->GetCredentialId();
        info.templateId = credInfo->GetTemplateId();
        info.authType = credInfo->GetAuthType();
        if (info.authType == PIN) {
            auto userInfo = UserIdmDatabase::Instance().GetSecUserInfo(userId);
            if (userInfo == nullptr) {
                IAM_LOGE("failed to get userInfo");
                return GENERAL_ERROR;
            }
            info.pinType = userInfo->GetPinSubType();
        }
        credInfoList.push_back(info);
    }
    return SUCCESS;
}

int32_t UserIdmService::GetCredentialInfo(int32_t userId, AuthType authType,
    const sptr<IdmGetCredInfoCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    std::vector<CredentialInfo> credInfoList;
    int32_t ret = GetCredentialInfoInner(userId, authType, credInfoList);
    if (ret != SUCCESS) {
        IAM_LOGE("GetCredentialInfoInner fail, ret: %{public}d", ret);
        credInfoList.clear();
    }
    callback->OnCredentialInfos(credInfoList);

    return ret;
}

int32_t UserIdmService::GetSecInfoInner(int32_t userId, SecUserInfo &secUserInfo)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    auto userInfos = UserIdmDatabase::Instance().GetSecUserInfo(userId);
    if (userInfos == nullptr) {
        IAM_LOGE("current userid %{public}d is not existed", userId);
        return INVALID_PARAMETERS;
    }
    std::vector<std::shared_ptr<EnrolledInfoInterface>> enrolledInfos = userInfos->GetEnrolledInfo();
    for (const auto &enrolledInfo : enrolledInfos) {
        if (enrolledInfo == nullptr) {
            IAM_LOGE("enrolledInfo is nullptr");
            return GENERAL_ERROR;
        }
        EnrolledInfo info = {enrolledInfo->GetAuthType(), enrolledInfo->GetEnrolledId()};
        secUserInfo.enrolledInfo.push_back(info);
    }
    secUserInfo.secureUid = userInfos->GetSecUserId();
    return SUCCESS;
}

int32_t UserIdmService::GetSecInfo(int32_t userId, const sptr<IdmGetSecureUserInfoCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    SecUserInfo secUserInfo = {};
    int32_t ret = GetSecInfoInner(userId, secUserInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("GetSecInfoInner fail, ret: %{public}d", ret);
        secUserInfo.secureUid = 0;
        secUserInfo.enrolledInfo.clear();
    }
    callback->OnSecureUserInfo(secUserInfo);

    return ret;
}

bool UserIdmService::CheckEnrollPermissionAndEnableStatus(
    const std::shared_ptr<ContextCallback> &contextCallback, AuthType authType)
{
    Attributes extraInfo;
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return false;
    }

    if (!SystemParamManager::GetInstance().IsAuthTypeEnable(authType)) {
        IAM_LOGE("authType not support");
        contextCallback->OnResult(TYPE_NOT_SUPPORT, extraInfo);
        return false;
    }
    return true;
}

void UserIdmService::StartEnroll(Enrollment::EnrollmentPara &para,
    const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo)
{
    auto context = ContextFactory::CreateEnrollContext(para, contextCallback);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    auto cleaner = ContextHelper::Cleaner(context);
    contextCallback->SetCleaner(cleaner);

    if (!context->Start()) {
        IAM_LOGE("failed to start enroll");
        contextCallback->OnResult(context->GetLatestError(), extraInfo);
    }
}

void UserIdmService::AddCredential(int32_t userId, const CredentialPara &credPara,
    const sptr<IdmCallbackInterface> &callback, bool isUpdate)
{
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(callback,
        isUpdate ? TRACE_UPDATE_CREDENTIAL : TRACE_ADD_CREDENTIAL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    std::string callerName = "";
    int32_t callerType = 0;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);
    contextCallback->SetTraceAuthType(credPara.authType);

    if (!CheckEnrollPermissionAndEnableStatus(contextCallback, credPara.authType)) {
        IAM_LOGE("CheckEnrollPermissionAndEnableStatus fail");
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();
    Enrollment::EnrollmentPara para = {};
    para.authType = credPara.authType;
    para.userId = userId;
    para.pinType = credPara.pinType;
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.token = credPara.token;
    para.isUpdate = isUpdate;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.callerName = callerName;
    para.callerType = callerType;
    StartEnroll(para, contextCallback, extraInfo);
}

void UserIdmService::UpdateCredential(int32_t userId, const CredentialPara &credPara,
    const sptr<IdmCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    auto credInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId, credPara.authType);
    if (credInfos.empty()) {
        IAM_LOGE("current userid %{public}d has no credential for type %{public}u", userId, credPara.authType);
        Attributes extraInfo;
        callback->OnResult(NOT_ENROLLED, extraInfo);
        return;
    }

    AddCredential(userId, credPara, callback, true);
}

int32_t UserIdmService::Cancel(int32_t userId)
{
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    if (!UserIdmSessionController::Instance().IsSessionOpened(userId)) {
        IAM_LOGE("both user id and challenge are invalid");
        return GENERAL_ERROR;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return CancelCurrentEnroll();
}

void UserIdmService::CancelCurrentEnrollIfExist()
{
    if (ContextPool::Instance().Select(CONTEXT_ENROLL).size() == 0) {
        return;
    }

    IAM_LOGI("cancel current enroll due to new add credential request or delete");
    CancelCurrentEnroll();
}

int32_t UserIdmService::CancelCurrentEnroll()
{
    IAM_LOGD("start");
    auto contextList = ContextPool::Instance().Select(CONTEXT_ENROLL);
    int32_t ret = GENERAL_ERROR;
    for (const auto &context : contextList) {
        if (auto ctx = context.lock(); ctx != nullptr) {
            IAM_LOGE("stop the old context %{public}s", GET_MASKED_STRING(ctx->GetContextId()).c_str());
            ctx->Stop();
            ContextPool::Instance().Delete(ctx->GetContextId());
            ret = SUCCESS;
        }
    }
    IAM_LOGI("result %{public}d", ret);
    return ret;
}

int32_t UserIdmService::EnforceDelUser(int32_t userId, const sptr<IdmCallbackInterface> &callback)
{
    IAM_LOGI("to delete userid: %{public}d", userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ENFORCE_DELETE_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = 0;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceUserId(userId);

    if (!IpcCommon::CheckPermission(*this, ENFORCE_USER_IDM)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    auto userInfo = UserIdmDatabase::Instance().GetSecUserInfo(userId);
    if (userInfo == nullptr) {
        IAM_LOGE("current userid %{public}d is not existed", userId);
        contextCallback->OnResult(INVALID_PARAMETERS, extraInfo);
        return INVALID_PARAMETERS;
    }
    int32_t ret = EnforceDelUserInner(userId, contextCallback, "EnforceDeleteUser");
    if (ret != SUCCESS) {
        IAM_LOGE("failed to enforce delete user");
        static_cast<void>(extraInfo.SetUint64Value(Attributes::ATTR_CREDENTIAL_ID, 0));
        contextCallback->OnResult(ret, extraInfo);
        return ret;
    }

    IAM_LOGI("delete user success");
    contextCallback->OnResult(SUCCESS, extraInfo);
    return SUCCESS;
}

void UserIdmService::DelUser(int32_t userId, const std::vector<uint8_t> authToken,
    const sptr<IdmCallbackInterface> &callback)
{
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_DELETE_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    std::string callerName = "";
    int32_t callerType = 0;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);

    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    std::vector<uint8_t> rootSecret;
    int32_t ret = UserIdmDatabase::Instance().DeleteUser(userId, authToken, credInfos, rootSecret);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete user");
        contextCallback->OnResult(ret, extraInfo);
        return;
    }
    if (!extraInfo.SetUint8ArrayValue(Attributes::ATTR_OLD_ROOT_SECRET, rootSecret)) {
        IAM_LOGE("set rootsecret to extraInfo failed");
        contextCallback->OnResult(ret, extraInfo);
        return;
    }
    SetAuthTypeTrace(credInfos, contextCallback);

    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos, "DeleteUser");
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
    }
    IAM_LOGI("delete user end");
    PublishEventAdapter::PublishDeletedEvent(userId);
    PublishEventAdapter::PublishCredentialUpdatedEvent(userId, PIN, 0);
    contextCallback->OnResult(ret, extraInfo);
}

void UserIdmService::DelCredential(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t> &authToken, const sptr<IdmCallbackInterface> &callback)
{
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_DELETE_CREDENTIAL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }
    std::string callerName = "";
    int32_t callerType = 0;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);

    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    std::shared_ptr<CredentialInfoInterface> oldInfo;
    auto ret = UserIdmDatabase::Instance().DeleteCredentialInfo(userId, credentialId, authToken, oldInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete CredentialInfo");
        contextCallback->OnResult(ret, extraInfo);
        return;
    }
    if (oldInfo != nullptr) {
        contextCallback->SetTraceAuthType(oldInfo->GetAuthType());
    }

    IAM_LOGI("delete credentialInfo success");
    std::vector<std::shared_ptr<CredentialInfoInterface>> list = {oldInfo};
    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(list, "DeleteTemplate");
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
    }

    contextCallback->OnResult(ret, extraInfo);
    if (oldInfo != nullptr) {
        auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId, oldInfo->GetAuthType());
        PublishEventAdapter::PublishCredentialUpdatedEvent(userId, oldInfo->GetAuthType(), credentialInfos.size());
    }
}

int UserIdmService::Dump(int fd, const std::vector<std::u16string> &args)
{
    IAM_LOGI("start");
    if (fd < 0) {
        IAM_LOGE("invalid parameters");
        dprintf(fd, "Invalid parameters.\n");
        return INVALID_PARAMETERS;
    }
    std::string arg0 = (args.empty() ? "" : Str16ToStr8(args[0]));
    if (arg0.empty() || arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "      -h: command help.\n");
        dprintf(fd, "      -l: active user info dump.\n");
        return SUCCESS;
    }
    if (arg0.compare("-l") != 0) {
        IAM_LOGE("invalid option");
        dprintf(fd, "Invalid option\n");
        return GENERAL_ERROR;
    }

    std::optional<int32_t> activeUserId;
    if (IpcCommon::GetActiveUserId(activeUserId) != SUCCESS) {
        dprintf(fd, "Internal error.\n");
        IAM_LOGE("failed to get active id");
        return GENERAL_ERROR;
    }
    dprintf(fd, "Active user is %d\n", activeUserId.value());
    auto userInfo = UserIdmDatabase::Instance().GetSecUserInfo(activeUserId.value());
    if (userInfo == nullptr) {
        IAM_LOGE("userInfo is null");
        return SUCCESS;
    }
    auto enrolledInfo = userInfo->GetEnrolledInfo();
    for (auto &info : enrolledInfo) {
        if (info != nullptr) {
            dprintf(fd, "AuthType %s is enrolled.\n", Common::AuthTypeToStr(info->GetAuthType()));
        }
    }
    return SUCCESS;
}

void UserIdmService::SetAuthTypeTrace(const std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos,
    const std::shared_ptr<ContextCallback> &contextCallback)
{
    uint32_t authTypeTrace = 0;
    for (const auto &credInfo : credInfos) {
        if (credInfo == nullptr) {
            IAM_LOGE("credInfo is nullptr");
            continue;
        }
        authTypeTrace |= static_cast<uint32_t>(credInfo->GetAuthType());
    }
    contextCallback->SetTraceAuthType(static_cast<int32_t>(authTypeTrace));
}

int32_t UserIdmService::EnforceDelUserInner(int32_t userId, std::shared_ptr<ContextCallback> callbackForTrace,
    std::string changeReasonTrace)
{
    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().DeleteUserEnforce(userId, credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to enforce delete user, ret:%{public}d", ret);
        return ret;
    }
    SetAuthTypeTrace(credInfos, callbackForTrace);
    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos, changeReasonTrace);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
        // The caller doesn't need to care executor delete result.
        return SUCCESS;
    }

    PublishEventAdapter::PublishDeletedEvent(userId);
    PublishEventAdapter::PublishCredentialUpdatedEvent(userId, PIN, 0);
    IAM_LOGI("delete user success, userId:%{public}d", userId);
    return SUCCESS;
}

void UserIdmService::ClearRedundancyCredentialInner()
{
    IAM_LOGE("start");
    std::vector<int32_t> accountInfo;
    int32_t ret = IpcCommon::GetAllUserId(accountInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("GetAllUserId failed");
        return;
    }

    auto userInfos = UserIdmDatabase::Instance().GetAllExtUserInfo();
    if (userInfos.empty()) {
        IAM_LOGE("no userInfo");
        return;
    }
    std::string callerName = "";
    int32_t callerType = 0;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));

    for (const auto &iter : userInfos) {
        int32_t userId = iter->GetUserId();
        auto callbackForTrace = ContextCallback::NewDummyInstance(TRACE_DELETE_REDUNDANCY);
        if (callbackForTrace == nullptr) {
            IAM_LOGE("failed to get callbackForTrace");
            continue;
        }
        callbackForTrace->SetTraceUserId(userId);
        callbackForTrace->SetTraceCallerName(callerName);
        callbackForTrace->SetTraceCallerType(callerType);
        std::vector<int32_t>::iterator it = std::find(accountInfo.begin(), accountInfo.end(), userId);
        if (it == accountInfo.end()) {
            ret = EnforceDelUserInner(userId, callbackForTrace, "DeleteRedundancy");
            Attributes extraInfo;
            callbackForTrace->OnResult(ret, extraInfo);
            IAM_LOGE("ClearRedundancytCredential, userId: %{public}d", userId);
        }
    }
}

void UserIdmService::ClearRedundancyCredential(const sptr<IdmCallbackInterface> &callback)
{
    IAM_LOGE("start");
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(callback, NO_NEED_TRACE);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        callback->OnResult(GENERAL_ERROR, extraInfo);
        return;
    }

    if (!IpcCommon::CheckPermission(*this, CLEAR_REDUNDANCY_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    this->ClearRedundancyCredentialInner();
    contextCallback->OnResult(SUCCESS, extraInfo);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS