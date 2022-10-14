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
#include "enroll_context.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "resource_node_utils.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

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
    IAM_LOGI("%{public}s success", GetDescription());
    return true;
}

void EnrollContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s receive result code %{public}d", GetDescription(), resultCode);
    uint64_t credentialId = 0;
    std::vector<uint8_t> rootSecret;
    bool updateRet = UpdateScheduleResult(scheduleResultAttr, credentialId, rootSecret);
    if (!updateRet) {
        IAM_LOGE("%{public}s UpdateScheduleResult fail", GetDescription());
        if (resultCode == SUCCESS) {
            resultCode = GetLatestError();
        }
    }
    InvokeResultCallback(resultCode, credentialId, rootSecret);
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
    uint64_t &credentialId, std::vector<uint8_t> &rootSecret)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(enroll_ != nullptr, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleResultAttr != nullptr, false);
    std::vector<uint8_t> scheduleResult;
    bool getResultCodeRet = scheduleResultAttr->GetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet == true, false);
    std::shared_ptr<CredentialInfo> infoToDel;
    bool updateRet = enroll_->Update(scheduleResult, credentialId, infoToDel, rootSecret);
    if (!updateRet) {
        IAM_LOGE("%{public}s enroll update fail", GetDescription());
        SetLatestError(enroll_->GetLatestError());
        return updateRet;
    }
    if (infoToDel == nullptr) {
        IAM_LOGI("no credential to delete");
    } else {
        std::vector<std::shared_ptr<CredentialInfo>> credInfos = {infoToDel};
        int32_t ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(credInfos);
        if (ret != SUCCESS) {
            IAM_LOGE("failed to delete executor info, error code : %{public}d", ret);
        }
    }
    return true;
}

void EnrollContext::InvokeResultCallback(int32_t resultCode, const uint64_t credentialId,
    const std::vector<uint8_t> &rootSecret) const
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    Attributes finalResult;
    bool setCredIdRet = finalResult.SetUint64Value(Attributes::ATTR_CREDENTIAL_ID, credentialId);
    IF_FALSE_LOGE_AND_RETURN(setCredIdRet == true);
    if (rootSecret.size() != 0) {
        bool setRootSecret = finalResult.SetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, rootSecret);
        IF_FALSE_LOGE_AND_RETURN(setRootSecret == true);
    }
    callback_->OnResult(resultCode, finalResult);
    IAM_LOGI("%{public}s invoke result callback success", GetDescription());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
