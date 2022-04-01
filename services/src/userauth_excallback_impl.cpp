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

#include "userauth_excallback_impl.h"

#include <cinttypes>

#include <iservice_registry.h>
#include <securec.h>
#include <system_ability_definition.h>

#include "coauth_info_define.h"
#include "thread_groups.h"
#include "userauth_async_proxy.h"
#include "userauth_datamgr.h"
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using namespace OHOS::UserIAM::Utils;
const static std::string GROUP_AUTH = "GROUP_AUTH";
std::mutex UserAuthCallbackImplCoAuth::coAuthCallbackMutex_;
std::map<uint64_t, std::shared_ptr<CoAuth::CoAuthCallback>> UserAuthCallbackImplCoAuth::saveCoAuthCallback_;

UserAuthCallbackImplSetProp::UserAuthCallbackImplSetProp(const sptr<IUserAuthCallback> &impl)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplSetProp impl callback is nullptr");
        return;
    }
    callback_ = impl;
}

void UserAuthCallbackImplSetProp::OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplSetProp OnResult start");

    if (callback_ == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplSetProp callback_ is nullptr");
    } else {
        callback_->onSetExecutorProperty(result);
    }
}

UserAuthCallbackImplSetPropFreeze::UserAuthCallbackImplSetPropFreeze(std::vector<uint64_t> templateIds,
    UserAuthToken authToken, FreezeInfo freezeInfo)
{
    templateIds_.clear();
    templateIds_.assign(templateIds.begin(), templateIds.end());
    resultCode_ = freezeInfo.resultCode;
    authToken_ = authToken;
    authType_ = freezeInfo.authType;
    pkgName_ = freezeInfo.pkgName;
    callerUid_ = freezeInfo.callerID;
}

void UserAuthCallbackImplSetPropFreeze::OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplSetPropFreeze result is %{public}u", result);
}

UserAuthCallbackImplCoAuth::UserAuthCallbackImplCoAuth(const sptr<IUserAuthCallback> &impl,
    const CoAuthInfo &coAuthInfo, bool resultFlag)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplCoAuth impl callback is nullptr");
        return;
    }
    callback_ = impl;
    authType_ = coAuthInfo.authType;
    callbackCount_ = coAuthInfo.sessionIds.size();
    callbackContextId_ = coAuthInfo.contextID;
    pkgName_ = coAuthInfo.pkgName;
    isResultDoneFlag_ = resultFlag;
    callerUid_ = coAuthInfo.callerID;
    userId_ = coAuthInfo.userID;
}

void UserAuthCallbackImplCoAuth::OnFinish(uint32_t resultCode, std::vector<uint8_t> &scheduleToken)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplCoAuth OnFinish start");
    AuthResult authResult;
    std::vector<uint8_t> scheduleToken_;
    scheduleToken_.assign(scheduleToken.begin(), scheduleToken.end());

    auto task = [self = shared_from_this(), resultCode, scheduleToken_]() {
        self->OnFinishHandle(resultCode, scheduleToken_);
    };

    bool ret = IamThreadGroups::GetInstance()->PostTask(GROUP_AUTH, callbackContextId_, task);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_SERVICE, "OnFinish ContextThreadPool AddTask failed");
        callback_->onResult(BUSY, authResult);
        isResultDoneFlag_ = true;
        return;
    }
}

void UserAuthCallbackImplCoAuth::OnAcquireInfo(uint32_t acquire)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplCoAuth OnAcquireInfo start");

    auto task = [self = shared_from_this(), acquire]() { self->OnAcquireInfoHandle(acquire); };

    bool ret = IamThreadGroups::GetInstance()->PostTask(GROUP_AUTH, callbackContextId_, task);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_SERVICE, "OnAcquireInfoHandle ContextThreadPool AddTask failed");
        isResultDoneFlag_ = true;
        return;
    }
}

void UserAuthCallbackImplCoAuth::OnFinishHandleExtend(int32_t userId, SetPropertyRequest setPropertyRequest,
    AuthResult authResult, int32_t ret, UserAuthToken authToken)
{
    if (authType_ == UserAuth::PIN) {
        USERAUTH_HILOGD(MODULE_SERVICE, "auth type is pin");
        setPropertyRequest.authType = UserAuth::FACE;
        setPropertyRequest.key = SetPropertyType::THAW_TEMPLATE;
        CallerInfo callerInfo;
        callerInfo.callerUID = callerUid_;
        callerInfo.userID = userId;
        callerInfo.pkgName = pkgName_;
        UserAuthAdapter::GetInstance().CoAuthSetPropAuthInfo(callerInfo, ret, authToken, setPropertyRequest);
    }
}

void UserAuthCallbackImplCoAuth::DealFinishData(std::vector<uint64_t> sessionIds)
{
    if (sessionIds.size() != 0) {
        for (auto const &item : sessionIds) {
            UserAuthAdapter::GetInstance().Cancel(item);
        }
    }
    UserAuthDataMgr::GetInstance().DeleteContextId(callbackContextId_);
    UserAuthCallbackImplCoAuth::DeleteCoAuthCallback(callbackContextId_);
    isResultDoneFlag_ = true;
    return;
}

void UserAuthCallbackImplCoAuth::OnFinishHandle(uint32_t resultCode, std::vector<uint8_t> scheduleToken)
{
    UserAuthToken authToken = {};
    std::vector<uint64_t> sessionIds;
    SetPropertyRequest setPropertyRequest;
    GetPropertyRequest getPropertyRequest;
    AuthResult authResult;
    CallerInfo callerInfo;
    int32_t ret = GENERAL_ERROR;
    std::lock_guard<std::mutex> lock(mutex_);
    callerInfo.callerUID = callerUid_;
    callerInfo.userID = userId_;
    callerInfo.pkgName = pkgName_;
    USERAUTH_HILOGD(MODULE_SERVICE, "OnFinishHandle scheduleTokensize:%{public}zu, resultCode:%{public}u",
        scheduleToken.size(), resultCode);
    callbackNowCount_++;
    if (isResultDoneFlag_) {
        return;
    }
    if (resultCode != CANCELED) {
        ret =
            UserAuthAdapter::GetInstance().RequestAuthResult(callbackContextId_, scheduleToken, authToken, sessionIds);
    }
    if (ret == E_RET_UNDONE) {
        if (callbackNowCount_ == callbackCount_) {
            USERAUTH_HILOGD(MODULE_SERVICE, "RequestAuthResult E_RET_UNDONE");
            UserAuthDataMgr::GetInstance().DeleteContextId(callbackContextId_);
            UserAuthCallbackImplCoAuth::DeleteCoAuthCallback(callbackContextId_);
            callback_->onResult(GENERAL_ERROR, authResult);
            isResultDoneFlag_ = true;
        }
        return;
    }
    if (resultCode == LOCKED && authType_ == PIN) {
        USERAUTH_HILOGD(MODULE_SERVICE, "resultCode is LOCKED");
        setPropertyRequest.authType = FACE;
        setPropertyRequest.key = SetPropertyType::FREEZE_TEMPLATE;
        UserAuthAdapter::GetInstance().CoAuthSetPropAuthInfo(callerInfo, resultCode, authToken, setPropertyRequest);
    }
    if (ret == SUCCESS) {
        OnFinishHandleExtend(userId_, setPropertyRequest, authResult, ret, authToken);
    }
    getPropertyRequest.authType = authType_;
    getPropertyRequest.keys.push_back(UserAuth::REMAIN_TIMES);
    getPropertyRequest.keys.push_back(UserAuth::FREEZING_TIME);
    UserAuthAdapter::GetInstance().GetPropAuthInfoCoAuth(callerInfo, resultCode, authToken, getPropertyRequest,
        callback_);
    DealFinishData(sessionIds);
}

void UserAuthCallbackImplCoAuth::OnAcquireInfoHandle(uint32_t acquire)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplCoAuth OnAcquireInfoHandle start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (isResultDoneFlag_) {
        return;
    }
    int32_t module = static_cast<int32_t>(authType_);
    uint32_t acquireInfo = acquire;
    int32_t extraInfo = 0;
    callback_->onAcquireInfo(module, acquireInfo, extraInfo);
}

int32_t UserAuthCallbackImplCoAuth::SaveCoAuthCallback(uint64_t contextId,
    std::shared_ptr<CoAuth::CoAuthCallback> coAuthCallback)
{
    std::lock_guard<std::mutex> lock(coAuthCallbackMutex_);
    auto retain = IamThreadGroups::GetInstance()->RetainTaskThread(GROUP_AUTH, contextId);
    if (!retain) {
        USERAUTH_HILOGD(MODULE_SERVICE, "Retain coAuth thread failed");
        return FAIL;
    }
    auto result = saveCoAuthCallback_.try_emplace(contextId, coAuthCallback);
    if (!result.second) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Save coAuth callback failed");
        return FAIL;
    }
    return SUCCESS;
}

int32_t UserAuthCallbackImplCoAuth::DeleteCoAuthCallback(uint64_t contextId)
{
    std::lock_guard<std::mutex> lock(coAuthCallbackMutex_);

    (void)IamThreadGroups::GetInstance()->ReleaseTaskThread(GROUP_AUTH, contextId);
    std::map<uint64_t, std::shared_ptr<CoAuth::CoAuthCallback>>::iterator iter = saveCoAuthCallback_.find(contextId);
    if (iter != saveCoAuthCallback_.end()) {
        saveCoAuthCallback_.erase(iter);
        USERAUTH_HILOGD(MODULE_SERVICE, "contextId 0xXXXX%{public}04" PRIx64 " is deleted", MASK & contextId);
        return SUCCESS;
    }
    USERAUTH_HILOGE(MODULE_SERVICE, "contextId is not found");
    return FAIL;
}

UserAuthCallbackImplIdmGetProp::UserAuthCallbackImplIdmGetProp(const sptr<IUserAuthCallback> &impl,
    GetPropertyRequest request, uint64_t callerUID, std::string pkgName)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplIdmGetProp impl callback is nullptr");
        return;
    }
    callback_ = impl;
    request_.authType = request.authType;
    request_.keys.clear();
    request_.keys.assign(request.keys.begin(), request.keys.end());
    pkgName_ = pkgName;
    callerUid_ = callerUID;
}

void UserAuthCallbackImplIdmGetProp::OnGetInfo(std::vector<UserIDM::CredentialInfo> &info)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIdmGetProp OnGetInfo start");
    ExecutorProperty executorProperty = {};
    if (info.size() == 0) {
        executorProperty.result = FAIL;
        callback_->onExecutorPropertyInfo(executorProperty);
        return;
    }
    uint64_t tmp = info.begin()->templateId;
    int32_t ret = UserAuthAdapter::GetInstance().GetExecutorProp(callerUid_, pkgName_, tmp, request_, executorProperty);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GetExecutorProp failed");
    }
    callback_->onExecutorPropertyInfo(executorProperty);
}

UserAuthCallbackImplIdmCoAuthGetPropFreeze::UserAuthCallbackImplIdmCoAuthGetPropFreeze(uint64_t callerUid,
    std::string pkgName, int32_t resultCode, UserAuthToken authToken, SetPropertyRequest request)
{
    authToken_ = authToken;
    resultCode_ = resultCode;
    request_ = request;
    pkgName_ = pkgName;
    callerUid_ = callerUid;
}

void UserAuthCallbackImplIdmCoAuthGetPropFreeze::OnGetInfo(std::vector<UserIDM::CredentialInfo> &info)
{
    CallerInfo callerInfo;
    callerInfo.callerUID = callerUid_;
    callerInfo.userID = 0;
    callerInfo.pkgName = pkgName_;

    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIdmCoAuthGetPropFreeze OnGetInfo start");
    std::vector<uint64_t> templateIds;
    AuthResult authResult;
    if (info.size() == 0) {
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIdmCoAuthGetPropFreeze OnGetInfo no data");
        authResult.token.resize(sizeof(UserAuthToken));
        if (memcpy_s(&authResult.token[0], authResult.token.size(), &authToken_, sizeof(UserAuthToken)) != EOK) {
            USERAUTH_HILOGE(MODULE_SERVICE, "copy authToken_ error");
        }
        return;
    }
    templateIds.clear();
    for (auto const &item : info) {
        templateIds.push_back(item.templateId);
    }
    UserAuthAdapter::GetInstance().SetPropAuthInfo(callerInfo, resultCode_, authToken_, request_, templateIds);
}

UserAuthCallbackImplIdmGetPropCoAuth::UserAuthCallbackImplIdmGetPropCoAuth(const sptr<IUserAuthCallback> &impl,
    uint64_t callerUid, std::string pkgName, int32_t resultCode, UserAuthToken authToken, GetPropertyRequest request)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplIdmGetPropCoAuth impl callback is nullptr");
        return;
    }
    callback_ = impl;
    authToken_ = authToken;
    resultCode_ = resultCode;
    request_ = request;
    pkgName_ = pkgName;
    callerUid_ = callerUid;
}

void UserAuthCallbackImplIdmGetPropCoAuth::OnGetInfo(std::vector<UserIDM::CredentialInfo> &info)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIdmGetPropCoAuth OnGetInfo start");
    ExecutorProperty executorProperty;
    AuthResult authResult;
    if (info.size() == 0) {
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIdmGetPropCoAuth OnGetInfo no data");
        executorProperty.result = GENERAL_ERROR;
        authResult.token.resize(sizeof(UserAuthToken));
        if (memcpy_s(&authResult.token[0], authResult.token.size(), &authToken_, sizeof(UserAuthToken)) != EOK) {
            USERAUTH_HILOGE(MODULE_SERVICE, "copy authToken_ error");
        }
        authResult.freezingTime = 0;
        authResult.remainTimes = 0;
        callback_->onResult(resultCode_, authResult);
        return;
    }
    uint64_t tmp = info.begin()->templateId;
    int32_t ret = UserAuthAdapter::GetInstance().GetExecutorProp(callerUid_, pkgName_, tmp, request_, executorProperty);
    if (ret != SUCCESS) {
        executorProperty.freezingTime = 0;
        executorProperty.remainTimes = 0;
    }
    authResult.freezingTime = executorProperty.freezingTime;
    authResult.remainTimes = executorProperty.remainTimes;
    authResult.token.resize(sizeof(UserAuthToken));
    if (memcpy_s(&authResult.token[0], authResult.token.size(), &authToken_, sizeof(UserAuthToken)) != EOK) {
        USERAUTH_HILOGE(MODULE_SERVICE, "copy authToken_ error");
    }
    callback_->onResult(resultCode_, authResult);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
