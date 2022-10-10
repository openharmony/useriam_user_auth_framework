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
#include "simple_auth_context.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
SimpleAuthContext::SimpleAuthContext(uint64_t contextId, std::shared_ptr<Authentication> auth,
    std::shared_ptr<ContextCallback> callback)
    : BaseContext("SimpleAuth", contextId, callback),
      auth_(auth)
{
}

ContextType SimpleAuthContext::GetContextType() const
{
    return CONTEXT_SIMPLE_AUTH;
}

bool SimpleAuthContext::OnStart()
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, false);
    bool startRet = auth_->Start(scheduleList_, shared_from_this());
    if (!startRet) {
        IAM_LOGE("%{public}s auth start fail", GetDescription());
        SetLatestError(auth_->GetLatestError());
        return startRet;
    }
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList_.size() == 1, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList_[0] != nullptr, false);
    bool startScheduleRet = scheduleList_[0]->StartSchedule();
    IF_FALSE_LOGE_AND_RETURN_VAL(startScheduleRet, false);
    IAM_LOGI("%{public}s success", GetDescription());
    return true;
}

void SimpleAuthContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGI("%{public}s receive result code %{public}d", GetDescription(), resultCode);
    Authentication::AuthResultInfo resultInfo = {};
    bool updateRet = UpdateScheduleResult(scheduleResultAttr, resultInfo);
    if (!updateRet) {
        IAM_LOGE("%{public}s UpdateScheduleResult fail", GetDescription());
        if (resultCode == SUCCESS) {
            resultCode = GetLatestError();
        }
        resultInfo.result = resultCode;
    }
    InvokeResultCallback(resultInfo);
    IAM_LOGI("%{public}s on result %{public}d finish", GetDescription(), resultCode);
}

bool SimpleAuthContext::OnStop()
{
    IAM_LOGI("%{public}s start", GetDescription());
    if (scheduleList_.size() == 1 && scheduleList_[0] != nullptr) {
        scheduleList_[0]->StopSchedule();
    }

    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, false);
    bool cancelRet = auth_->Cancel();
    if (!cancelRet) {
        IAM_LOGE("%{public}s auth stop fail", GetDescription());
        SetLatestError(auth_->GetLatestError());
        return cancelRet;
    }
    return true;
}

bool SimpleAuthContext::UpdateScheduleResult(const std::shared_ptr<Attributes> &scheduleResultAttr,
    Authentication::AuthResultInfo &resultInfo)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleResultAttr != nullptr, false);
    std::vector<uint8_t> scheduleResult;
    bool getResultCodeRet = scheduleResultAttr->GetUint8ArrayValue(Attributes::ATTR_RESULT, scheduleResult);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet == true, false);
    bool updateRet = auth_->Update(scheduleResult, resultInfo);
    if (!updateRet) {
        IAM_LOGE("%{public}s auth update fail", GetDescription());
        SetLatestError(auth_->GetLatestError());
        return updateRet;
    }
    return true;
}

void SimpleAuthContext::InvokeResultCallback(const Authentication::AuthResultInfo &resultInfo) const
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    Attributes finalResult;
    bool setResultCodeRet = finalResult.SetInt32Value(Attributes::ATTR_RESULT_CODE, resultInfo.result);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet == true);
    bool setFreezingTimeRet = finalResult.SetInt32Value(Attributes::ATTR_FREEZING_TIME, resultInfo.freezingTime);
    IF_FALSE_LOGE_AND_RETURN(setFreezingTimeRet == true);
    bool setUserIdRet = finalResult.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, resultInfo.remainTimes);
    IF_FALSE_LOGE_AND_RETURN(setUserIdRet == true);
    if (resultInfo.token.size() != 0) {
        bool setSignatureResult = finalResult.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, resultInfo.token);
        IF_FALSE_LOGE_AND_RETURN(setSignatureResult == true);
    }
    if (resultInfo.rootSecret.size() != 0) {
        bool setRootSecret = finalResult.SetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, resultInfo.rootSecret);
        IF_FALSE_LOGE_AND_RETURN(setRootSecret == true);
    }
    callback_->OnResult(resultInfo.result, finalResult);
    IAM_LOGI("%{public}s invoke result callback success", GetDescription());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
