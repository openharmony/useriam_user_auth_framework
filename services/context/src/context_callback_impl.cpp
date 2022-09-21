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
#include "context_callback_impl.h"

#include <sstream>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_ptr.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
ContextCallbackImpl::ContextCallbackImpl(sptr<IamCallbackInterface> iamCallback, OperationType operationType)
    : iamCallback_(iamCallback)
{
    metaData_.operationType = operationType;
    metaData_.startTime = std::chrono::steady_clock::now();
    std::ostringstream ss;
    ss << "IDM(operation:" << operationType << ")";
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>(ss.str());
}

void ContextCallbackImpl::OnAcquireInfo(ExecutorRole src, int32_t moduleType,
    const std::vector<uint8_t> &acquireMsg) const
{
    if (iamCallback_ == nullptr) {
        IAM_LOGE("iam callback is nullptr");
        return;
    }
    int32_t acquireInfo;
    if (Common::UnpackInt32(acquireMsg, 0, acquireInfo) != SUCCESS) {
        IAM_LOGE("failed to unpack acquireMsg");
        return;
    }
    Attributes attr = {};
    iamCallback_->OnAcquireInfo(moduleType, acquireInfo, attr);
}

void ContextCallbackImpl::OnResult(int32_t resultCode, const Attributes &finalResult)
{
    int32_t remainTime;
    int32_t freezingTime;
    metaData_.operationResult = resultCode;
    if (finalResult.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, remainTime)) {
        metaData_.remainTime = remainTime;
    }
    if (finalResult.GetInt32Value(Attributes::ATTR_FREEZING_TIME, freezingTime)) {
        metaData_.freezingTime = freezingTime;
    }
    metaData_.endTime = std::chrono::steady_clock::now();

    if (iamCallback_ != nullptr) {
        iamCallback_->OnResult(resultCode, finalResult);
    }
    
    ContextCallbackNotifyListener::GetInstance().Process(metaData_);
    if (stopCallback_ != nullptr) {
        stopCallback_();
    }
}

void ContextCallbackImpl::SetTraceUserId(int32_t userId)
{
    metaData_.userId = userId;
}

void ContextCallbackImpl::SetTraceRemainTime(int32_t remainTime)
{
    metaData_.remainTime = remainTime;
}

void ContextCallbackImpl::SetTraceFreezingTime(int32_t freezingTime)
{
    metaData_.freezingTime = freezingTime;
}

void ContextCallbackImpl::SetTraceSdkVersion(int32_t version)
{
    metaData_.sdkVersion = version;
}

void ContextCallbackImpl::SetTraceCallingUid(uint64_t callingUid)
{
    metaData_.callingUid = callingUid;
}

void ContextCallbackImpl::SetTraceAuthType(AuthType authType)
{
    metaData_.authType = authType;
}

void ContextCallbackImpl::SetTraceAuthTrustLevel(AuthTrustLevel atl)
{
    metaData_.atl = atl;
}

void ContextCallbackImpl::SetCleaner(Context::ContextStopCallback callback)
{
    stopCallback_ = callback;
}

void ContextCallbackNotifyListener::AddNotifier(const Notify &notify)
{
    notifierList_.emplace_back(notify);
}

void ContextCallbackNotifyListener::Process(const MetaData &metaData)
{
    for (const auto &notify : notifierList_) {
        if (notify != nullptr) {
            notify(metaData);
        }
    }
}

std::shared_ptr<ContextCallback> ContextCallback::NewInstance(sptr<IamCallbackInterface> iamCallback,
    OperationType operationType)
{
    if (iamCallback == nullptr) {
        IAM_LOGE("iam callback is nullptr, parameter is invalid");
        return nullptr;
    }
    return UserIam::Common::MakeShared<ContextCallbackImpl>(iamCallback, operationType);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS