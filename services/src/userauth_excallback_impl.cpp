/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "userauth_common.h"
#include "userauth_datamgr.h"
#include "coauth_info_define.h"
#include "userauth_async_proxy.h"
#include "securec.h"

#include <iservice_registry.h>
#include <system_ability_definition.h>

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
std::mutex UserAuthCallbackImplCoAuth::coauthCallbackmutex_;
std::map<uint64_t, std::shared_ptr<CoAuth::CoAuthCallback>> UserAuthCallbackImplCoAuth::saveCoauthCallback_;
UserAuthCallbackImplSetProp::UserAuthCallbackImplSetProp(const sptr<IUserAuthCallback>& impl)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplSetProp impl callback is Null");
        return ;
    }
    callback_ = impl;
}
void UserAuthCallbackImplSetProp::OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplSetProp OnResult enter");

    if (callback_ == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplSetProp callback_ is Null");
    } else {
        callback_->onSetExecutorProperty(result);
    }
}

UserAuthCallbackImplSetPropFreez::UserAuthCallbackImplSetPropFreez(const sptr<IUserAuthCallback>& impl,
                                                                   std::vector<uint64_t> templateIds,
                                                                   UserAuthToken authToken, FreezInfo freezInfo)
{
    callback_ = impl;
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
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplSetPropFreez OnResult enter");
    int32_t ret = SUCCESS;
    AuthResult authResult;
    ExecutorProperty executorProperty;
    GetPropertyRequest getPropertyRequest;
    if (result != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplSetPropFreez is fail");
    }

    getPropertyRequest.authType = authType_;
    getPropertyRequest.keys.push_back(AUTH_SUB_TYPE);
    getPropertyRequest.keys.push_back(REMAIN_TIMES);
    getPropertyRequest.keys.push_back(FREEZING_TIME);
    if (callback_ == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplSetPropFreez callback_ is Null");
        return;
    } else {
        if (templateIds_.size() == 0) {
            callback_->onResult(GENERAL_ERROR, authResult);
            return;
        }
        ret = UserAuthAdapter::GetInstance().GetExecutorProp(callerUid_, pkgName_, templateIds_.front(),
            getPropertyRequest, executorProperty);
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
}

UserAuthCallbackImplCoAuth::UserAuthCallbackImplCoAuth(const sptr<IUserAuthCallback>& impl,
                                                       CoAuthInfo coAuthInfo, bool resultFlag)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplCoAuth impl callback is Null");
        return ;
    }
    callback_ = impl;
    authType_ = coAuthInfo.authType;
    callbackCount_ = coAuthInfo.sessionIds.size();
    callbackContextID_ = coAuthInfo.contextID;
    pkgName_ = coAuthInfo.pkgName;
    callbackResultFlag_ = resultFlag;
    callerUid_ = coAuthInfo.callerID;
}
void UserAuthCallbackImplCoAuth::OnFinish(uint32_t resultCode, std::vector<uint8_t> &scheduleToken)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplCoAuth OnFinish enter");
    AuthResult authResult;
    std::vector<uint8_t> scheduleToken_;
    scheduleToken_.assign(scheduleToken.begin(), scheduleToken.end());
    auto task = std::bind(&UserAuthCallbackImplCoAuth::OnFinishHandle, this, resultCode, scheduleToken_);
    bool ret = ContextThreadPool::GetInstance().AddTask(callbackContextID_, task);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_SERVICE, "OnFinish ContextThreadPool is BUSY");
        callback_->onResult(BUSY, authResult);
        callbackResultFlag_ = true;
        return;
    }
}
void UserAuthCallbackImplCoAuth::OnAcquireInfo(uint32_t acquire)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplCoAuth OnAcquireInfo enter");

    auto task = std::bind(&UserAuthCallbackImplCoAuth::OnAcquireInfoHandle, this, acquire);
    bool ret = ContextThreadPool::GetInstance().AddTask(callbackContextID_, task);
    if (!ret) {
        USERAUTH_HILOGE(MODULE_SERVICE, "OnAcquireInfoHandle ContextThreadPool is BUSY");
        callbackResultFlag_ = true;
        return;
    }
}
void UserAuthCallbackImplCoAuth::OnFinishHandle(uint32_t resultCode, std::vector<uint8_t> scheduleToken)
{
    UserAuthToken authToken;
    std::vector<uint64_t> sessionIds;
    SetPropertyRequest setPropertyRequest;
    GetPropertyRequest getPropertyRequest;
    AuthResult authResult;
    std::lock_guard<std::mutex> lock(mutex_);
    USERAUTH_HILOGD(MODULE_SERVICE, "OnFinishHandle scheduleTokensize:%{public}d, resultCode:%{public}d",
        scheduleToken.size(), resultCode);
    callbackNowCount_++;
    if (callbackResultFlag_) {
        return;
    }
    int32_t ret = UserAuthAdapter::GetInstance().RequestAuthResult(callbackContextID_,
        scheduleToken, authToken, sessionIds);
    if (resultCode != LOCKED) {
        if (ret == E_RET_UNDONE) {
            if (callbackNowCount_ == callbackCount_) {
                USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplCoAuth E_RET_UNDONE");
                UserAuthDataMgr::GetInstance().DeleteContextID(callbackContextID_);
                UserAuthCallbackImplCoAuth::DeleteCoauthCallback(callbackContextID_);
                callback_->onResult(GENERAL_ERROR, authResult);
                callbackResultFlag_ = true;
            }
            return ;
        } else if (ret == SUCCESS) {
            if (authType_ == UserAuth::PIN) {
                USERAUTH_HILOGD(MODULE_SERVICE, "RequestAuthResult SUCCESS");
                setPropertyRequest.authType = authType_;
                setPropertyRequest.key = SetPropertyType::THAW_TEMPLATE;
                UserAuthAdapter::GetInstance().CoauthSetPropAuthInfo(ret, callerUid_, pkgName_,
                    authToken, setPropertyRequest, callback_);
            } else {
                USERAUTH_HILOGD(MODULE_SERVICE, "RequestAuthResult SUCCESS NOT INFO");
                authResult.token.resize(sizeof(UserAuthToken));
                if (memcpy_s(&authResult.token[0], authResult.token.size(), &authToken, sizeof(UserAuthToken)) != EOK) {
                    USERAUTH_HILOGE(MODULE_SERVICE, "copy authToken error");
                }
                authResult.remainTimes = 0;
                authResult.freezingTime = 0;
                callback_->onResult(ret, authResult);
            }
        } else {
            USERAUTH_HILOGD(MODULE_SERVICE, "RequestAuthResult NOT SUCCESS");
            getPropertyRequest.authType = authType_;
            getPropertyRequest.keys.push_back(UserAuth::REMAIN_TIMES);
            getPropertyRequest.keys.push_back(UserAuth::FREEZING_TIME);
            UserAuthAdapter::GetInstance().GetPropAuthInfoCoauth(callerUid_, pkgName_, ret,
                authToken, getPropertyRequest, callback_);
        }
    } else {
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplCoAuth resultCode == LOCKED");
        setPropertyRequest.authType = authType_;
        setPropertyRequest.key = SetPropertyType::FREEZE_TEMPLATE;
        UserAuthAdapter::GetInstance().CoauthSetPropAuthInfo(ret, callerUid_, pkgName_, authToken, setPropertyRequest,
                                                             callback_);
    }
    if (sessionIds.size() != 0) {
        for (std::vector<uint64_t>::iterator iter = sessionIds.begin(); iter != sessionIds.end(); ++iter) {
            UserAuthAdapter::GetInstance().Cancel(*iter);
        }
    }
    UserAuthDataMgr::GetInstance().DeleteContextID(callbackContextID_);
    UserAuthCallbackImplCoAuth::DeleteCoauthCallback(callbackContextID_);
    callbackResultFlag_ = true;
}

void UserAuthCallbackImplCoAuth::OnAcquireInfoHandle(uint32_t acquire)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplCoAuth OnAcquireInfoHandle");
    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackResultFlag_) {
        return;
    }
    int32_t module = static_cast<int32_t>(authType_);
    uint32_t acquireInfo = acquire;
    int32_t extraInfo = 0;
    callback_->onAcquireInfo(module, acquireInfo, extraInfo);
}

int32_t UserAuthCallbackImplCoAuth::SaveCoauthCallback(uint64_t contextId, std::shared_ptr<CoAuth::CoAuthCallback> coauthCallback)
{
    int32_t resultCode = SUCCESS;
    std::lock_guard<std::mutex> lock(coauthCallbackmutex_);
    saveCoauthCallback_.insert(std::make_pair(contextId, coauthCallback));
    if (saveCoauthCallback_.begin() != saveCoauthCallback_.end()) {
        resultCode = SUCCESS;
        USERAUTH_HILOGD(MODULE_SERVICE, "Save coauth callback success");
    } else {
        resultCode = FAIL;
        USERAUTH_HILOGE(MODULE_SERVICE, "Save coauth callback failed");
    }
    return resultCode;
}

int32_t UserAuthCallbackImplCoAuth::DeleteCoauthCallback(uint64_t contextId)
{
    int32_t resultCode = SUCCESS;
    std::lock_guard<std::mutex> lock(coauthCallbackmutex_);
    std::map<uint64_t, std::shared_ptr<CoAuth::CoAuthCallback>> ::iterator iter = saveCoauthCallback_.find(contextId);
    if (iter != saveCoauthCallback_.end()) {
        saveCoauthCallback_.erase(iter);
        resultCode = SUCCESS;
        USERAUTH_HILOGD(MODULE_SERVICE, "contextId XXXX%{public}04llx is deleted", contextId);
    } else {
        resultCode = FAIL;
        USERAUTH_HILOGE(MODULE_SERVICE, "contextId is not found and do not delete callback");
    }
    return resultCode;
}

UserAuthCallbackImplIDMGetPorp::UserAuthCallbackImplIDMGetPorp(const sptr<IUserAuthCallback>& impl,
                                                               GetPropertyRequest requst, uint64_t callerUID,
                                                               std::string pkgName)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorp  impl callback is Null");
        return ;
    }
    callback_ = impl;
    requst_.authType = requst.authType;
    requst_.keys.clear();
    requst_.keys.assign(requst.keys.begin(), requst.keys.end());
    pkgName_ = pkgName;
    callerUid_ = callerUID;
}
void UserAuthCallbackImplIDMGetPorp::OnGetInfo(std::vector<UserIDM::CredentialInfo>& info)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorp  OnGetInfo enter");
    ExecutorProperty executorProperty;
    if (info.size() == 0) {
        executorProperty.result = GENERAL_ERROR;
        callback_->onExecutorPropertyInfo(executorProperty);
        return;
    }
    uint64_t tmp = info.begin()->templateId;
    UserAuthAdapter::GetInstance().GetExecutorProp(callerUid_, pkgName_, tmp, requst_, executorProperty);
    callback_->onExecutorPropertyInfo(executorProperty);
}

UserAuthCallbackImplIDMCothGetPorpFreez::UserAuthCallbackImplIDMCothGetPorpFreez(
    const sptr<IUserAuthCallback>& impl, uint64_t callerUid, std::string pkgName, int32_t resultCode,
    UserAuthToken authToken, SetPropertyRequest requset)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplIDMCothGetPorpFreez impl callback is Null");
        return ;
    }
    callback_ = impl;
    authToken_ = authToken;
    resultCode_ = resultCode;
    requset_ = requset;
    pkgName_ = pkgName;
    callerUid_ = callerUid;
}
void UserAuthCallbackImplIDMCothGetPorpFreez::OnGetInfo(std::vector<UserIDM::CredentialInfo>& info)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMCothGetPorpFreez  OnGetInfo enter");
    std::vector<uint64_t> templateIds;
    AuthResult authResult;
    if (info.size() == 0) {
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMCothGetPorpFreez OnGetInfo error");
        authResult.token.resize(sizeof(UserAuthToken));
        if (memcpy_s(&authResult.token[0], authResult.token.size(), &authToken_, sizeof(UserAuthToken)) != EOK) {
            USERAUTH_HILOGE(MODULE_SERVICE, "copy authToken_ error");
        }
        authResult.freezingTime = 0;
        authResult.remainTimes = 0;
        callback_->onResult(resultCode_, authResult);
        return;
    }
    templateIds.clear();
    for (std::vector<UserIDM::CredentialInfo>::const_iterator iter = info.begin(); iter != info.end(); ++iter) {
        templateIds.push_back((*iter).templateId);
    }
    UserAuthAdapter::GetInstance().SetPropAuthInfo(callerUid_, pkgName_, resultCode_, authToken_, requset_,
        templateIds, callback_);
}

UserAuthCallbackImplIDMGetPorpCoauth::UserAuthCallbackImplIDMGetPorpCoauth(
    const sptr<IUserAuthCallback>& impl, uint64_t callerUid, std::string pkgName, int32_t resultCode,
    UserAuthToken authToken, GetPropertyRequest requset)
{
    if (impl == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorpCoauth impl callback is Null");
        return ;
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
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorpCoauth OnGetInfo enter");
    int32_t ret = 0;
    ExecutorProperty executorProperty;
    AuthResult authResult;
    if (info.size() == 0) {
        USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthCallbackImplIDMGetPorpCoauth OnGetInfo error");
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
    ret = UserAuthAdapter::GetInstance().GetExecutorProp(callerUid_, pkgName_, tmp, requset_, executorProperty);
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
