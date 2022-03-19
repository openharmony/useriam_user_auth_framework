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
#include <system_ability_definition.h>
#include "securec.h"
#include "coauth_info_define.h"
#include "userauth_hilog_wrapper.h"
#include "userauth_datamgr.h"
#include "userauth_async_proxy.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
std::mutex UserAuthCallbackImplCoAuth::coauthCallbackmutex_;
std::map<uint64_t, std::shared_ptr<CoAuth::CoAuthCallback>> UserAuthCallbackImplCoAuth::saveCoauthCallback_;

UserAuthCallbackImplSetProp::UserAuthCallbackImplSetProp(const sptr<IUserAuthCallback>& impl)
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

UserAuthCallbackImplSetPropFreez::UserAuthCallbackImplSetPropFreez(std::vector<uint64_t> templateIds,
    UserAuthToken authToken, FreezInfo freezInfo)
{
    templateIds_.clear();
    templateIds_.assign(templateIds.begin(), templateIds.end());
    resultCode_ = freezInfo.resultCode;
    authToken_ = authToken;
    authType_ = freezInfo.authType;
    pkgName_ = freezInfo.pkgName;
    callerUid_ = freezInfo.callerID;
}

void UserAuthCallbackImplSetPropFreez::OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplSetPropFreez result is %{public}u", result);
}

UserAuthCallbackImplCoAuth::UserAuthCallbackImplCoAuth(const sptr<IUserAuthCallback>& impl,
    CoAuthInfo coAuthInfo, bool resultFlag)
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
    auto task = std::bind(&UserAuthCallbackImplCoAuth::OnFinishHandle, this, resultCode, scheduleToken_);
    bool ret = ContextThreadPool::GetInstance().AddTask(callbackContextId_, task);
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

    auto task = std::bind(&UserAuthCallbackImplCoAuth::OnAcquireInfoHandle, this, acquire);
    bool ret = ContextThreadPool::GetInstance().AddTask(callbackContextId_, task);
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
        UserAuthAdapter::GetInstance().CoauthSetPropAuthInfo(callerInfo, ret, authToken, setPropertyRequest);
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
    UserAuthCallbackImplCoAuth::DeleteCoauthCallback(callbackContextId_);
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
        ret = UserAuthAdapter::GetInstance().RequestAuthResult(callbackContextId_,
        scheduleToken, authToken, sessionIds);
    }
    if (ret == E_RET_UNDONE) {
        if (callbackNowCount_ == callbackCount_) {
            USERAUTH_HILOGD(MODULE_SERVICE, "RequestAuthResult E_RET_UNDONE");
            UserAuthDataMgr::GetInstance().DeleteContextId(callbackContextId_);
            UserAuthCallbackImplCoAuth::DeleteCoauthCallback(callbackContextId_);
            callback_->onResult(GENERAL_ERROR, authResult);
            isResultDoneFlag_ = true;
        }
        return;
    }
    if (resultCode == LOCKED && authType_ == PIN) {
        USERAUTH_HILOGD(MODULE_SERVICE, "resultCode is LOCKED");
        setPropertyRequest.authType = FACE;
        setPropertyRequest.key = SetPropertyType::FREEZE_TEMPLATE;
        UserAuthAdapter::GetInstance().CoauthSetPropAuthInfo(callerInfo, resultCode, authToken,
            setPropertyRequest);
    }
    if (ret == SUCCESS) {
        OnFinishHandleExtend(userId_, setPropertyRequest, authResult, ret, authToken);
    }
    getPropertyRequest.authType = authType_;
    getPropertyRequest.keys.push_back(UserAuth::REMAIN_TIMES);
    getPropertyRequest.keys.push_back(UserAuth::FREEZING_TIME);
    UserAuthAdapter::GetInstance().GetPropAuthInfoCoauth(callerInfo, resultCode,
        authToken, getPropertyRequest, callback_);
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

int32_t UserAuthCallbackImplCoAuth::SaveCoauthCallback(uint64_t contextId,
    std::shared_ptr<CoAuth::CoAuthCallback> coauthCallback)
{
    std::lock_guard<std::mutex> lock(coauthCallbackmutex_);
    saveCoauthCallback_.insert(std::make_pair(contextId, coauthCallback));
    if (saveCoauthCallback_.begin() != saveCoauthCallback_.end()) {
        USERAUTH_HILOGD(MODULE_SERVICE, "Save coauth callback success");
        return SUCCESS;
    }
    USERAUTH_HILOGE(MODULE_SERVICE, "Save coauth callback failed");
    return FAIL;
}

int32_t UserAuthCallbackImplCoAuth::DeleteCoauthCallback(uint64_t contextId)
{
    std::lock_guard<std::mutex> lock(coauthCallbackmutex_);
    std::map<uint64_t, std::shared_ptr<CoAuth::CoAuthCallback>> ::iterator iter = saveCoauthCallback_.find(contextId);
    if (iter != saveCoauthCallback_.end()) {
        saveCoauthCallback_.erase(iter);
        USERAUTH_HILOGD(MODULE_SERVICE, "contextId XXXX%{public}04" PRIx64 " is deleted", contextId);
        return SUCCESS;
    }
    USERAUTH_HILOGE(MODULE_SERVICE, "contextId is not found");
    return FAIL;
}

UserAuthCallbackImplIDMGetPorp::UserAuthCallbackImplIDMGetPorp(const sptr<IUserAuthCallback>& impl,
    GetPropertyRequest request, uint64_t callerUID, std::string pkgName)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorp impl callback is nullptr");
        return;
    }
    callback_ = impl;
    request_.authType = request.authType;
    request_.keys.clear();
    request_.keys.assign(request.keys.begin(), request.keys.end());
    pkgName_ = pkgName;
    callerUid_ = callerUID;
}

void UserAuthCallbackImplIDMGetPorp::OnGetInfo(std::vector<UserIDM::CredentialInfo>& info)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorp OnGetInfo start");
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

UserAuthCallbackImplIDMCothGetPorpFreez::UserAuthCallbackImplIDMCothGetPorpFreez(
    uint64_t callerUid, std::string pkgName, int32_t resultCode,
    UserAuthToken authToken, SetPropertyRequest requset)
{
    authToken_ = authToken;
    resultCode_ = resultCode;
    requset_ = requset;
    pkgName_ = pkgName;
    callerUid_ = callerUid;
}

void UserAuthCallbackImplIDMCothGetPorpFreez::OnGetInfo(std::vector<UserIDM::CredentialInfo>& info)
{
    CallerInfo callerInfo;
    callerInfo.callerUID = callerUid_;
    callerInfo.userID = 0;
    callerInfo.pkgName = pkgName_;

    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMCothGetPorpFreez OnGetInfo start");
    std::vector<uint64_t> templateIds;
    AuthResult authResult;
    if (info.size() == 0) {
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMCothGetPorpFreez OnGetInfo no data");
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
    UserAuthAdapter::GetInstance().SetPropAuthInfo(callerInfo, resultCode_, authToken_, requset_,
        templateIds);
}

UserAuthCallbackImplIDMGetPorpCoauth::UserAuthCallbackImplIDMGetPorpCoauth(
    const sptr<IUserAuthCallback>& impl, uint64_t callerUid, std::string pkgName, int32_t resultCode,
    UserAuthToken authToken, GetPropertyRequest requset)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorpCoauth impl callback is nullptr");
        return;
    }
    callback_ = impl;
    authToken_ = authToken;
    resultCode_ = resultCode;
    requset_ = requset;
    pkgName_ = pkgName;
    callerUid_ = callerUid;
}

void UserAuthCallbackImplIDMGetPorpCoauth::OnGetInfo(std::vector<UserIDM::CredentialInfo>& info)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorpCoauth OnGetInfo start");
    ExecutorProperty executorProperty;
    AuthResult authResult;
    if (info.size() == 0) {
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorpCoauth OnGetInfo no data");
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
    int32_t ret = UserAuthAdapter::GetInstance().GetExecutorProp(callerUid_, pkgName_, tmp, requset_, executorProperty);
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
} // namespace UserIam
} // namespace OHOS
