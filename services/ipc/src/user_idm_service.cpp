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

#include "context_appstate_observer.h"
#include "context_helper.h"
#include "context_pool.h"
#include "hdi_wrapper.h"
#include "iam_callback_proxy.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_defines.h"
#include "iam_time.h"
#include "ipc_common.h"
#include "ipc_skeleton.h"
#include "iam_common_defines.h"
#include "load_mode_handler.h"
#include "publish_event_adapter.h"
#include "resource_node_pool.h"
#include "resource_node_utils.h"
#include "service_init_manager.h"
#include "user_idm_database.h"
#include "user_idm_session_controller.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
REGISTER_SYSTEM_ABILITY_BY_ID(UserIdmService, SUBSYS_USERIAM_SYS_ABILITY_USERIDM, true);
constexpr int32_t USERIAM_IPC_THREAD_NUM = 4;
UserIdmService::UserIdmService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), UserIdmStub(true)
{
}

void UserIdmService::OnStart()
{
    IAM_LOGI("Sa start UserIdmService");
    IPCSkeleton::SetMaxWorkThreadNum(USERIAM_IPC_THREAD_NUM);
    if (!Publish(this)) {
        IAM_LOGE("failed to publish service");
    }
    ServiceInitManager::GetInstance().OnIdmServiceStart();
}

void UserIdmService::OnStop()
{
    IAM_LOGI("Sa stop UserIdmService");
    ServiceInitManager::GetInstance().OnIdmServiceStop();
}

int32_t UserIdmService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
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

int32_t UserIdmService::CloseSession(int32_t userId)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    if (!UserIdmSessionController::Instance().CloseSession(userId)) {
        IAM_LOGE("failed to get close session");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserIdmService::GetCredentialInfoInner(int32_t userId, AuthType authType,
    std::vector<CredentialInfo> &credInfoList)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType, credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
            userId, authType);
        return GENERAL_ERROR;
    }

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
        info.pinType = credInfo->GetAuthSubType();
        credInfoList.push_back(info);
    }
    return SUCCESS;
}

int32_t UserIdmService::GetCredentialInfo(int32_t userId, int32_t authType,
    const sptr<IIdmGetCredInfoCallback> &callback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    std::vector<IpcCredentialInfo> ipcCredInfoList;
    std::vector<CredentialInfo> credInfoList;
    int32_t ret = GetCredentialInfoInner(userId, static_cast<AuthType>(authType), credInfoList);
    if (ret != SUCCESS) {
        IAM_LOGE("GetCredentialInfoInner fail, ret: %{public}d", ret);
        credInfoList.clear();
    }
    
    for (auto &iter : credInfoList) {
        IpcCredentialInfo ipcCredInfo;
        ipcCredInfo.authType = static_cast<int32_t>(iter.authType);
        ipcCredInfo.pinType = static_cast<int32_t>(iter.pinType.value_or(PIN_SIX));
        ipcCredInfo.credentialId = iter.credentialId;
        ipcCredInfo.templateId = iter.templateId;
        ipcCredInfoList.push_back(ipcCredInfo);
    }

    auto retCode = callback->OnCredentialInfos(ret, ipcCredInfoList);
    if (retCode != SUCCESS) {
        IAM_LOGE("OnCredentialInfos fail, ret: %{public}d", retCode);
    }
    return ret;
}

int32_t UserIdmService::GetSecInfoInner(int32_t userId, SecUserInfo &secUserInfo)
{
    IAM_LOGI("start");
    if (!IpcCommon::CheckPermission(*this, USE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }
    std::shared_ptr<SecureUserInfoInterface> userInfos = nullptr;
    int32_t ret = UserIdmDatabase::Instance().GetSecUserInfo(userId, userInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get secUserInfo fail, ret:%{public}d, userId:%{public}d", ret, userId);
        return ret;
    }
    if (userInfos == nullptr) {
        IAM_LOGE("current userid %{public}d is not existed", userId);
        return GENERAL_ERROR;
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

int32_t UserIdmService::GetSecInfo(int32_t userId, const sptr<IIdmGetSecureUserInfoCallback> &callback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    IpcSecUserInfo ipcSecUserInfo;
    SecUserInfo secUserInfo = {};
    int32_t ret = GetSecInfoInner(userId, secUserInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("GetSecInfoInner fail, ret: %{public}d", ret);
        secUserInfo.secureUid = 0;
        secUserInfo.enrolledInfo.clear();
    }

    for (auto &iter : secUserInfo.enrolledInfo) {
        IpcEnrolledInfo ipcEnrolledInfo;
        ipcEnrolledInfo.authType = static_cast<int32_t>(iter.authType);
        ipcEnrolledInfo.enrolledId = iter.enrolledId;
        ipcSecUserInfo.enrolledInfo.push_back(ipcEnrolledInfo);
    }

    auto retCode = callback->OnSecureUserInfo(ret, ipcSecUserInfo);
    if (retCode != SUCCESS) {
        IAM_LOGE("OnSecureUserInfo fail, ret: %{public}d", retCode);
    }
    return ret;
}

int32_t UserIdmService::StartEnroll(Enrollment::EnrollmentPara &para,
    const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo, bool needSubscribeAppState)
{
    if (!para.isUpdate && para.authType == PIN && !para.token.empty()) {
        IAM_LOGI("auth type is pin, clear token");
        para.token.clear();
    }

    auto context = ContextFactory::CreateEnrollContext(para, contextCallback, needSubscribeAppState);
    if (context == nullptr || !ContextPool::Instance().Insert(context)) {
        IAM_LOGE("failed to insert context");
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    contextCallback->SetTraceRequestContextId(context->GetContextId());
    auto cleaner = ContextHelper::Cleaner(context);
    contextCallback->SetCleaner(cleaner);

    if (!context->Start()) {
        IAM_LOGE("failed to start enroll");
        contextCallback->OnResult(context->GetLatestError(), extraInfo);
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserIdmService::AddCredential(int32_t userId, const IpcCredentialPara &ipcCredentialPara,
    const sptr<IIamCallback> &idmCallback, bool isUpdate)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback,
        isUpdate ? TRACE_UPDATE_CREDENTIAL : TRACE_ADD_CREDENTIAL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);
    contextCallback->SetTraceAuthType(static_cast<AuthType>(ipcCredentialPara.authType));
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();
    Enrollment::EnrollmentPara para = {};
    para.authType = static_cast<AuthType>(ipcCredentialPara.authType);
    para.userId = userId;
    para.pinType = static_cast<PinSubType>(ipcCredentialPara.pinType);
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.token = ipcCredentialPara.token;
    para.isUpdate = isUpdate;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.callerName = callerName;
    para.callerType = callerType;
    bool needSubscribeAppState = !IpcCommon::CheckPermission(*this, USER_AUTH_FROM_BACKGROUND);
    return StartEnroll(para, contextCallback, extraInfo, needSubscribeAppState);
}

int32_t UserIdmService::UpdateCredential(int32_t userId, const IpcCredentialPara &ipcCredentialPara,
    const sptr<IIamCallback> &idmCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    if (idmCallback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return INVALID_PARAMETERS;
    }

    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId,
        static_cast<AuthType>(ipcCredentialPara.authType), credInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d",
            ret, userId, ipcCredentialPara.authType);
        Attributes extraInfo;
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }

    if (credInfos.empty()) {
        IAM_LOGE("current userid %{public}d has no credential for type %{public}u",
            userId, ipcCredentialPara.authType);
        Attributes extraInfo;
        idmCallback->OnResult(NOT_ENROLLED, extraInfo.Serialize());
        return SUCCESS;
    }

    return AddCredential(userId, ipcCredentialPara, idmCallback, true);
}

int32_t UserIdmService::Cancel(int32_t userId)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
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
            IAM_LOGI("stop the old context %{public}s", GET_MASKED_STRING(ctx->GetContextId()).c_str());
            ctx->Stop();
            ContextPool::Instance().Delete(ctx->GetContextId());
            ret = SUCCESS;
        }
    }
    IAM_LOGI("result %{public}d", ret);
    return ret;
}

int32_t UserIdmService::EnforceDelUser(int32_t userId, const sptr<IIamCallback> &idmCallback)
{
    IAM_LOGI("to delete userid: %{public}d", userId);
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback, TRACE_ENFORCE_DELETE_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
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
    std::shared_ptr<SecureUserInfoInterface> userInfo = nullptr;
    int32_t ret = UserIdmDatabase::Instance().GetSecUserInfo(userId, userInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("get secUserInfo fail, ret:%{public}d, userId:%{public}d", ret, userId);
        contextCallback->OnResult(ret, extraInfo);
        return ret;
    }
    if (userInfo == nullptr) {
        IAM_LOGE("current userid %{public}d is not existed", userId);
        contextCallback->OnResult(GENERAL_ERROR, extraInfo);
        return GENERAL_ERROR;
    }
    ret = EnforceDelUserInner(userId, contextCallback, "EnforceDeleteUser");
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

int32_t UserIdmService::DelUser(int32_t userId, const std::vector<uint8_t> &authToken,
    const sptr<IIamCallback> &idmCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback, TRACE_DELETE_USER);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);

    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    std::vector<uint8_t> rootSecret;
    int32_t ret = UserIdmDatabase::Instance().DeleteUser(userId, authToken, credInfos, rootSecret);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete user");
        contextCallback->OnResult(ret, extraInfo);
        return ret;
    }
    ContextAppStateObserverManager::GetInstance().RemoveScreenLockState(userId);
    if (!extraInfo.SetUint8ArrayValue(Attributes::ATTR_OLD_ROOT_SECRET, rootSecret)) {
        IAM_LOGE("set rootsecret to extraInfo failed");
        contextCallback->OnResult(ret, extraInfo);
        return ret;
    }
    SetAuthTypeTrace(credInfos, contextCallback);
    contextCallback->OnResult(ret, extraInfo);

    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos, "DeleteUser");
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
    }
    IAM_LOGI("delete user end");
    PublishEventAdapter::GetInstance().PublishDeletedEvent(userId);
    PublishEventAdapter::GetInstance().PublishCredentialUpdatedEvent(userId, PIN, 0);
    return SUCCESS;
}

int32_t UserIdmService::DelCredential(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t> &authToken, const sptr<IIamCallback> &idmCallback)
{
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback, TRACE_DELETE_CREDENTIAL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);
    contextCallback->SetTraceUserId(userId);

    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    std::shared_ptr<CredentialInfoInterface> oldInfo;
    auto ret = UserIdmDatabase::Instance().DeleteCredentialInfo(userId, credentialId, authToken, oldInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete CredentialInfo");
        contextCallback->OnResult(ret, extraInfo);
        return ret;
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
        PublishCommonEvent(userId, credentialId, oldInfo->GetAuthType());
    }

    return SUCCESS;
}

int UserIdmService::Dump(int fd, const std::vector<std::u16string> &args)
{
    IAM_LOGI("start");
    if (fd < 0) {
        IAM_LOGE("invalid parameters");
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
    std::shared_ptr<SecureUserInfoInterface> userInfo = nullptr;
    int32_t ret = UserIdmDatabase::Instance().GetSecUserInfo(activeUserId.value(), userInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("get secUserInfo fail, ret:%{public}d, userId:%{public}d", ret, activeUserId.value());
        return GENERAL_ERROR;
    }
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
    ContextAppStateObserverManager::GetInstance().RemoveScreenLockState(userId);
    SetAuthTypeTrace(credInfos, callbackForTrace);
    ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos, changeReasonTrace);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
        // The caller doesn't need to care executor delete result.
        return SUCCESS;
    }

    PublishEventAdapter::GetInstance().PublishDeletedEvent(userId);
    PublishEventAdapter::GetInstance().PublishCredentialUpdatedEvent(userId, PIN, 0);
    IAM_LOGI("delete user success, userId:%{public}d", userId);
    return SUCCESS;
}

int32_t UserIdmService::ClearRedundancyCredentialInner(const std::string &callerName, int32_t callerType)
{
    IAM_LOGI("start");
    std::vector<int32_t> accountInfo;
    int32_t ret = IpcCommon::GetAllUserId(accountInfo);
    if (ret != SUCCESS) {
        IAM_LOGE("GetAllUserId failed");
        return IPC_ERROR;
    }

    std::vector<std::shared_ptr<UserInfoInterface>> userInfos;
    ret = UserIdmDatabase::Instance().GetAllExtUserInfo(userInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("GetAllExtUserInfo failed");
        return INVALID_HDI_INTERFACE;
    }

    if (userInfos.empty()) {
        IAM_LOGE("no userInfo");
        return SUCCESS;
    }

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
    return SUCCESS;
}

int32_t UserIdmService::ClearRedundancyCredential(const sptr<IIamCallback> &idmCallback)
{
    IAM_LOGI("start");
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(idmCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    auto contextCallback = ContextCallback::NewInstance(idmCallback, TRACE_DELETE_REDUNDANCY);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback");
        idmCallback->OnResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }

    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    contextCallback->SetTraceCallerName(callerName);
    contextCallback->SetTraceCallerType(callerType);

    if (!IpcCommon::CheckPermission(*this, CLEAR_REDUNDANCY_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        contextCallback->OnResult(CHECK_PERMISSION_FAILED, extraInfo);
        return CHECK_PERMISSION_FAILED;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    CancelCurrentEnrollIfExist();

    int32_t ret = ClearRedundancyCredentialInner(callerName, callerType);
    if (ret != SUCCESS) {
        IAM_LOGE("clearRedundancyCredentialInner fail, ret:%{public}d, ", ret);
    }
    contextCallback->OnResult(ret, extraInfo);
    return ret;
}

void UserIdmService::PublishCommonEvent(int32_t userId, uint64_t credentialId, AuthType authType)
{
    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType, credentialInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret, userId, authType);
        return;
    }
    PublishEventAdapter::GetInstance().PublishCredentialUpdatedEvent(userId, authType, credentialInfos.size());
    PublishEventAdapter::GetInstance().PublishUpdatedEvent(userId, credentialId);
}

int32_t UserIdmService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t UserIdmService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS