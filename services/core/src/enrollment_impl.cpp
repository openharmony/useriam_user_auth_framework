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
#include "enrollment_impl.h"

#include "hdi_wrapper.h"
#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "credential_info_impl.h"
#include "schedule_node_helper.h"
#include "user_idm_database.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

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

void EnrollmentImpl::SetLatestError(int32_t error)
{
    if (error != ResultCode::SUCCESS) {
        latestError_ = error;
    }
}

int32_t EnrollmentImpl::GetLatestError() const
{
    return latestError_;
}

void EnrollmentImpl::SetExecutorSensorHint(uint32_t executorSensorHint)
{
    executorSensorHint_ = executorSensorHint;
}

void EnrollmentImpl::SetAuthToken(const std::vector<uint8_t> &authToken)
{
    authToken_ = authToken;
}

void EnrollmentImpl::SetAccessTokenId(uint32_t tokenId)
{
    tokenId_ = tokenId;
}

uint32_t EnrollmentImpl::GetAccessTokenId() const
{
    return tokenId_;
}

void EnrollmentImpl::SetPinSubType(PinSubType pinSubType)
{
    pinSubType_ = pinSubType;
}

void EnrollmentImpl::SetIsUpdate(bool isUpdate)
{
    isUpdate_ = isUpdate;
}

bool EnrollmentImpl::Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
    std::shared_ptr<ScheduleNodeCallback> callback)
{
    IAM_LOGE("UserId:%{public}d AuthType:%{public}d", userId_, authType_);
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }
    // cache secUserId first in case of update
    if (isUpdate_ && !GetSecUserId(secUserId_)) {
        IAM_LOGE("get and cache secUserId fail");
        return false;
    }

    HdiScheduleInfo info = {};
    HdiEnrollParam param = {
        .authType = static_cast<HdiAuthType>(authType_),
        .executorSensorHint = executorSensorHint_,
    };
    IamHitraceHelper traceHelper("hdi BeginEnrollment");
    auto result = hdi->BeginEnrollmentV1_1(userId_, authToken_, param, info);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi BeginEnrollment failed, err is %{public}d", result);
        SetLatestError(result);
        return false;
    }

    std::vector<HdiScheduleInfo> infos = {};
    infos.emplace_back(info);

    ScheduleNodeHelper::NodeOptionalPara para;
    para.tokenId = tokenId_;

    if (!ScheduleNodeHelper::BuildFromHdi(infos, callback, scheduleList, para)) {
        IAM_LOGE("BuildFromHdi failed");
        return false;
    }

    running_ = true;
    return true;
}

bool EnrollmentImpl::GetSecUserId(std::optional<uint64_t> &secUserId)
{
    secUserId = std::nullopt;
    if (authType_ != PIN) {
        IAM_LOGI("no need return sec user id");
        return true;
    }
    auto userInfo = UserIdmDatabase::Instance().GetSecUserInfo(userId_);
    if (userInfo != nullptr) {
        secUserId = userInfo->GetSecUserId();
        return true;
    }

    // do not delete users in case of updates
    if (isUpdate_) {
        return false;
    }

    IAM_LOGE("current user id %{public}d get fail", userId_);
    std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
    if (UserIdmDatabase::Instance().DeleteUserEnforce(userId_, credInfos) != SUCCESS) {
        IAM_LOGE("failed to enforce delete user");
    }
    return false;
}

bool EnrollmentImpl::Update(const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
    std::shared_ptr<CredentialInfoInterface> &info, std::vector<uint8_t> &rootSecret,
    std::optional<uint64_t> &secUserId)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    HdiEnrollResultInfo resultInfo = {};
    auto result = hdi->UpdateEnrollmentResult(userId_, scheduleResult, resultInfo);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi UpdateEnrollmentResult failed, err is %{public}d, userId is %{public}d", result, userId_);
        SetLatestError(result);
        return false;
    }
    IAM_LOGI("hdi UpdateEnrollmentResult success, userId is %{public}d", userId_);

    credentialId = resultInfo.credentialId;
    rootSecret = resultInfo.rootSecret;
    if (isUpdate_) {
        secUserId = secUserId_;
    } else {
        if (!GetSecUserId(secUserId)) {
            IAM_LOGE("enroll get secUserId fail");
            return false;
        }
        IAM_LOGI("enroll not need to delete old cred");
        info = nullptr;
        return true;
    }

    info = Common::MakeShared<CredentialInfoImpl>(userId_, resultInfo.oldInfo);
    if (info == nullptr) {
        IAM_LOGE("bad alloc");
        return false;
    }
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
        SetLatestError(result);
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS