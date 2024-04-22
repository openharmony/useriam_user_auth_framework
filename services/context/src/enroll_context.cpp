/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "enroll_context.h"

#include "hisysevent_adapter.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "resource_node_utils.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
EnrollContext::EnrollContext(uint64_t contextId, std::shared_ptr<Enrollment> enroll,
    std::shared_ptr<ContextCallback> callback)
    : BaseContext("Enroll", contextId, callback),
      enroll_(enroll)
{
}

ContextType EnrollContext::GetContextType() const
{
    return CONTEXT_ENROLL;
}

uint32_t EnrollContext::GetTokenId() const
{
    return enroll_->GetAccessTokenId();
}

bool EnrollContext::OnStart()
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(enroll_ != nullptr, false);
    bool startRet = enroll_->Start(scheduleList_, shared_from_this());
    if (!startRet) {
        IAM_LOGE("%{public}s enroll start fail", GetDescription());
        SetLatestError(enroll_->GetLatestError());
        return startRet;
    }
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList_.size() == 1, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList_[0] != nullptr, false);
    bool startScheduleRet = scheduleList_[0]->StartSchedule();
    IF_FALSE_LOGE_AND_RETURN_VAL(startScheduleRet, false);
    IAM_LOGI("%{public}s Schedule:%{public}s Type:%{public}d success", GetDescription(),
        GET_MASKED_STRING(scheduleList_[0]->GetScheduleId()).c_str(), scheduleList_[0]->GetAuthType());
    return true;
}

void EnrollContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s receive result code %{public}d", GetDescription(), resultCode);
    uint64_t credentialId = 0;
    std::shared_ptr<UpdatePinParamInterface> pinInfo;
    std::optional<uint64_t> secUserId = std::nullopt;
    bool updateRet = UpdateScheduleResult(scheduleResultAttr, credentialId, pinInfo, secUserId);
    if (!updateRet) {
        IAM_LOGE("%{public}s UpdateScheduleResult fail", GetDescription());
        if (resultCode == SUCCESS) {
            resultCode = GetLatestError();
        }
    }
    InvokeResultCallback(resultCode, credentialId, pinInfo, secUserId);
    IAM_LOGI("%{public}s on result %{public}d finish", GetDescription(), resultCode);
}

bool EnrollContext::OnStop()
{
    IAM_LOGI("%{public}s start", GetDescription());
    if (scheduleList_.size() == 1 && scheduleList_[0] != nullptr) {
        scheduleList_[0]->StopSchedule();
    }

    IF_FALSE_LOGE_AND_RETURN_VAL(enroll_ != nullptr, false);
    bool cancelRet = enroll_->Cancel();
    if (!cancelRet) {
        IAM_LOGE("%{public}s enroll stop fail", GetDescription());
        SetLatestError(enroll_->GetLatestError());
        return cancelRet;
    }
    return true;
}

bool EnrollContext::UpdateScheduleResult(const std::shared_ptr<Attributes> &scheduleResultAttr,
    uint64_t &credentialId, std::shared_ptr<UpdatePinParamInterface> &pinInfo, std::optional<uint64_t> &secUserId)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(enroll_ != nullptr, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleResultAttr != nullptr, false);
    std::vector<uint8_t> scheduleResult;
    bool getResultCodeRet = scheduleResultAttr->GetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet == true, false);
    std::shared_ptr<CredentialInfoInterface> infoToDel;
    bool updateRet = enroll_->Update(scheduleResult, credentialId, infoToDel, pinInfo, secUserId);
    if (!updateRet) {
        IAM_LOGE("%{public}s enroll update fail", GetDescription());
        SetLatestError(enroll_->GetLatestError());
        return updateRet;
    }

    return true;
}

void EnrollContext::InvokeResultCallback(int32_t resultCode, const uint64_t credentialId,
    const std::shared_ptr<UpdatePinParamInterface> &pinInfo, std::optional<uint64_t> &secUserId) const
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    Attributes finalResult;
    if (secUserId.has_value()) {
        IAM_LOGI("%{public}s get sec user id has value", GetDescription());
        bool setSecUserIdRet = finalResult.SetUint64Value(Attributes::ATTR_SEC_USER_ID, secUserId.value());
        IF_FALSE_LOGE_AND_RETURN(setSecUserIdRet == true);
    }
    bool setCredIdRet = finalResult.SetUint64Value(Attributes::ATTR_CREDENTIAL_ID, credentialId);
    IF_FALSE_LOGE_AND_RETURN(setCredIdRet == true);
    if (pinInfo != nullptr) {
        bool setOldCredId = finalResult.SetUint64Value(Attributes::ATTR_OLD_CREDENTIAL_ID,
            pinInfo->GetOldCredentialId());
        IF_FALSE_LOGE_AND_RETURN(setOldCredId == true);
        std::vector<uint8_t> rootSecret = pinInfo->GetRootSecret();
        if (rootSecret.size() != 0) {
            bool setRootSecret = finalResult.SetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, rootSecret);
            IF_FALSE_LOGE_AND_RETURN(setRootSecret == true);
        }
        std::vector<uint8_t> oldRootSecret = pinInfo->GetOldRootSecret();
        if (oldRootSecret.size() != 0) {
            bool setRet = finalResult.SetUint8ArrayValue(Attributes::ATTR_OLD_ROOT_SECRET, oldRootSecret);
            IF_FALSE_LOGE_AND_RETURN(setRet == true);
        }
        std::vector<uint8_t> authToken = pinInfo->GetAuthToken();
        if (authToken.size() != 0) {
            bool setAuthToken = finalResult.SetUint8ArrayValue(Attributes::ATTR_AUTH_TOKEN, authToken);
            IF_FALSE_LOGE_AND_RETURN(setAuthToken == true);
        }
    }

    callback_->OnResult(resultCode, finalResult);
    IAM_LOGI("%{public}s invoke result callback success", GetDescription());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
