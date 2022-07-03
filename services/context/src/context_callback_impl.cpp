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
#include "iam_ptr.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
ContextCallbackImpl::ContextCallbackImpl(sptr<IdmCallback> idmCallback, OperationType operationType)
    : idmCallback_(idmCallback)
{
    metaData_.operationType = operationType;
    metaData_.startTime = std::chrono::steady_clock::now();
    std::ostringstream ss;
    ss << "IDM(operation:" << operationType << ")";
    iamHitraceHelper_ = UserIAM::Common::MakeShared<IamHitraceHelper>(ss.str());
}

ContextCallbackImpl::ContextCallbackImpl(sptr<UserAuthCallback> userAuthCallback, OperationType operationType)
    : userAuthCallback_(userAuthCallback)
{
    metaData_.operationType = operationType;
    metaData_.startTime = std::chrono::steady_clock::now();
    std::ostringstream ss;
    ss << "UserAuth(operation:" << operationType << ")";
    iamHitraceHelper_ = UserIAM::Common::MakeShared<IamHitraceHelper>(ss.str());
}

void ContextCallbackImpl::onAcquireInfo(ExecutorRole src, int32_t moduleType,
    const std::vector<uint8_t> &acquireMsg) const
{
    if (idmCallback_ != nullptr) {
        if (acquireMsg.size() != sizeof(int32_t)) {
            IAM_LOGE("acquireMsg size is invalid");
            return;
        }
        int32_t acquire = *(int32_t *)(const_cast<uint8_t *>(&acquireMsg[0]));
        Attributes attr = {};
        idmCallback_->OnAcquireInfo(moduleType, acquire, attr);
    }
    if (userAuthCallback_ != nullptr) {
        if (acquireMsg.size() != sizeof(int32_t)) {
            IAM_LOGE("acquireMsg size is invalid");
            return;
        }
        int32_t acquire = *(int32_t *)(const_cast<uint8_t *>(&acquireMsg[0]));
        userAuthCallback_->OnAcquireInfo(moduleType, acquire, 0);
    }
}

void ContextCallbackImpl::OnResult(int32_t resultCode, Attributes &finalResult)
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

    iamHitraceHelper_ = nullptr;
    if (idmCallback_ != nullptr) {
        idmCallback_->OnResult(resultCode, finalResult);
    }
    if (userAuthCallback_ != nullptr) {
        int32_t userId;
        auto isIdentify = finalResult.GetInt32Value(Attributes::ATTR_USER_ID, userId);
        if (isIdentify) {
            userAuthCallback_->OnIdentifyResult(resultCode, finalResult);
        } else {
            userAuthCallback_->OnAuthResult(resultCode, finalResult);
        }
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

std::shared_ptr<ContextCallback> ContextCallback::NewInstance(sptr<IdmCallback> idmCallback,
    OperationType operationType)
{
    if (idmCallback == nullptr) {
        IAM_LOGE("idmCallback is nullptr, parameter is invalid");
        return nullptr;
    }
    return UserIAM::Common::MakeShared<ContextCallbackImpl>(idmCallback, operationType);
}

std::shared_ptr<ContextCallback> ContextCallback::NewInstance(sptr<UserAuthCallback> userAuthCallback,
    OperationType operationType)
{
    if (userAuthCallback == nullptr) {
        IAM_LOGE("userAuthCallback is nullptr, parameter is invalid");
        return nullptr;
    }
    return UserIAM::Common::MakeShared<ContextCallbackImpl>(userAuthCallback, operationType);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
