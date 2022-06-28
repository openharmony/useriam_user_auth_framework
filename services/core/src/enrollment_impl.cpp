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
#include "enrollment_impl.h"

#include "hdi_wrapper.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "credential_info_impl.h"
#include "schedule_node_helper.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

using namespace OHOS::UserIAM::Common;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
EnrollmentImpl::EnrollmentImpl(int32_t userId, AuthType authType) : userId_(userId), authType_(authType)
{
}

EnrollmentImpl::~EnrollmentImpl()
{
    Cancel();
}

void EnrollmentImpl::SetExecutorSensorHint(uint32_t executorSensorHint)
{
    executorSensorHint_ = executorSensorHint;
}

void EnrollmentImpl::SetAuthToken(const std::vector<uint8_t> &authToken)
{
    authToken_ = authToken;
}

void EnrollmentImpl::SetCallingUid(uint32_t uid)
{
    uid_ = uid;
}

void EnrollmentImpl::SetPinSubType(PinSubType pinSubType)
{
    pinSubType_ = pinSubType;
}

bool EnrollmentImpl::Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
    std::shared_ptr<ScheduleNodeCallback> callback)
{
    using HdiScheduleInfo = OHOS::HDI::UserAuth::V1_0::ScheduleInfo;
    using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;
    using EnrollParam = OHOS::HDI::UserAuth::V1_0::EnrollParam;
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    HdiScheduleInfo info = {};
    EnrollParam param = {
        .authType = static_cast<HdiAuthType>(authType_),
        .executorSensorHint = executorSensorHint_,
    };
    auto result = hdi->BeginEnrollment(userId_, authToken_, param, info);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi BeginEnrollment failed, err is %{public}d", result);
        return false;
    }

    std::vector<HdiScheduleInfo> infos = {};
    infos.emplace_back(info);

    ScheduleNodeHelper::NodeOptionalPara para;
    para.uid = uid_;

    if (!ScheduleNodeHelper::BuildFromHdi(infos, callback, scheduleList, para)) {
        IAM_LOGE("BuildFromHdi failed");
        return false;
    }

    running_ = true;
    return true;
}

bool EnrollmentImpl::Update(const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
    std::shared_ptr<CredentialInfo> &info)
{
    using HdiCredentialInfo = OHOS::HDI::UserAuth::V1_0::CredentialInfo;

    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    HdiCredentialInfo oldInfo = {};
    auto result = hdi->UpdateEnrollmentResult(userId_, scheduleResult, credentialId, oldInfo);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi UpdateEnrollmentResult failed, err is %{public}d, userId is %{public}d", result, userId_);
        return false;
    }
    IAM_LOGI("hdi UpdateEnrollmentResult success, userId is %{public}d", userId_);
    auto infoRet = MakeShared<CredentialInfoImpl>(userId_, oldInfo);
    if (infoRet == nullptr) {
        IAM_LOGE("bad alloc");
        return false;
    }
    info = infoRet;

    return true;
}

bool EnrollmentImpl::Cancel()
{
    if (!running_) {
        return false;
    }
    running_ = false;

    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    auto result = hdi->CancelEnrollment(userId_);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi CancelEnrollment failed, err is %{public}d", result);
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS