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

#include "useridm_coauth_handler.h"
#include "useridm_hilog_wrapper.h"
#include "useridm_adapter.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
UserIDMCoAuthHandler::UserIDMCoAuthHandler(CoAuthType type, const uint64_t challenge, const uint64_t scheduleId,
    const std::shared_ptr<UserIDMModule>& data, const sptr<IIDMCallback>& callback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMCoAuthHandler constructor start");

    type_ = type;
    lastChallenge_ = challenge;
    lastScheduleId_ = scheduleId;
    dataCallback_ = data;
    innerCallback_ = callback;
    if (innerCallback_ == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: input callback is nullptr");
    }
}

int32_t UserIDMCoAuthHandler::OnFinishModify(uint32_t resultCode, std::vector<uint8_t>& scheduleToken,
    uint64_t& credentialId)
{
    if (innerCallback_ == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: innerCallback_ is nullptr");
        return INVALID_PARAMETERS;
    }
    uint64_t challenge = 0;
    uint64_t scheduleId = 0;
    if (dataCallback_ == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "dataCallback error: no found");
        return FAIL;
    }
    bool res = dataCallback_->CheckChallenge(challenge);
    if (!res) {
        USERIDM_HILOGE(MODULE_SERVICE, "check challenge num error: no challenge");
        return FAIL;
    }

    res = dataCallback_->CheckScheduleIdIsActive(scheduleId);
    if (res && (scheduleId == lastScheduleId_)) {
        CredentialInfo credentialInfo;
        UserIDMAdapter::GetInstance().UpdateCredential(scheduleToken, credentialId, credentialInfo);

        std::shared_ptr<UserIDMSetPropHandler> setPropCallback =
            std::make_shared<UserIDMSetPropHandler>(PIN, challenge, scheduleId, credentialId,
                dataCallback_, innerCallback_);
        AuthResPool::AuthAttributes condition;
        condition.SetUint32Value(AuthAttributeType::AUTH_PROPERTY_MODE, 0);
        condition.SetUint64Value(AuthAttributeType::AUTH_CALLER_UID, 0);
        condition.SetUint64Value(AuthAttributeType::AUTH_CREDENTIAL_ID, credentialInfo.credentialId);
        condition.SetUint32Value(AuthAttributeType::AUTH_TYPE, credentialInfo.authType);
        condition.SetUint64Value(AuthAttributeType::AUTH_TEMPLATE_ID, credentialInfo.templateId);
        CoAuth::CoAuth::GetInstance().SetExecutorProp(condition, setPropCallback);
        return SUCCESS;
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "scheduleId wrong");
        return FAIL;
    }
}

void UserIDMCoAuthHandler::OnFinish(uint32_t resultCode, std::vector<uint8_t>& scheduleToken)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMCoAuthHandler OnFinish start: %{public}u type_ is %{public}d",
        resultCode, type_);
    std::lock_guard<std::mutex> lock(mutex_);
    if (innerCallback_ == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: innerCallback_ is nullptr");
        return;
    }
    int32_t result = FAIL;
    uint64_t credentialId = 0;
    if (resultCode != SUCCESS) {
        dataCallback_->DeleteSessionId();
        RequestResult reqRet;
        reqRet.credentialId = credentialId;
        innerCallback_->OnResult(result, reqRet);
        return;
    }
    if ((type_ == ADD_PIN_CRED) || (type_ == ADD_FACE_CRED)) {
        uint64_t scheduleId = 0;
        bool res = dataCallback_->CheckScheduleIdIsActive(scheduleId);
        if (res && (scheduleId == lastScheduleId_)) {
            result = UserIDMAdapter::GetInstance().AddCredential(scheduleToken, credentialId);
            if (result != SUCCESS) {
                USERIDM_HILOGE(MODULE_SERVICE, "call TA info addCred failed");
            }
        }
        dataCallback_->DeleteSessionId();
        RequestResult reqRet;
        reqRet.credentialId = credentialId;
        innerCallback_->OnResult(result, reqRet);
    } else if (type_ == MODIFY_CRED) {
        result = OnFinishModify(resultCode, scheduleToken, credentialId);
        RequestResult reqRet;
        reqRet.credentialId = credentialId;
        innerCallback_->OnResult(result, reqRet);
        dataCallback_->DeleteSessionId();
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "callback type error: %{public}d", type_);
    }
}

void UserIDMCoAuthHandler::OnAcquireInfo(uint32_t acquire)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMCoAuthHandler OnAcquireInfo start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (innerCallback_ == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: innerCallback_ is nullptr");
        return;
    }

    if (type_ == ADD_FACE_CRED) {
        RequestResult reqRet = {};
        const int32_t faceModule = 1;
        innerCallback_->OnAcquireInfo(faceModule, acquire, reqRet);
    }
}

void UserIDMCoAuthHandler::ResetCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    innerCallback_ = nullptr;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
