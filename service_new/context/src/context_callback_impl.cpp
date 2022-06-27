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

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
ContextCallbackImpl::ContextCallbackImpl(sptr<IdmCallback> idmCallback) : idmCallback_(idmCallback)
{
    if (idmCallback_ == nullptr) {
        IAM_LOGE("idmCallback is nullptr, parameter is invalid");
    }
}

ContextCallbackImpl::ContextCallbackImpl(sptr<UserAuthCallback> userAuthCallback) : userAuthCallback_(userAuthCallback)
{
    if (userAuthCallback_ == nullptr) {
        IAM_LOGE("userAuthCallback is nullptr, parameter is invalid");
    }
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

void ContextCallbackImpl::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) const
{
    IF_FALSE_LOGE_AND_RETURN(finalResult != nullptr);
    if (idmCallback_ != nullptr) {
        idmCallback_->OnResult(resultCode, *finalResult);
    }
    if (userAuthCallback_ != nullptr) {
        int32_t userId;
        auto isIdentify = finalResult->GetInt32Value(Attributes::ATTR_USER_ID, userId);
        if (isIdentify) {
            userAuthCallback_->OnIdentifyResult(resultCode, *finalResult);
        } else {
            userAuthCallback_->OnAuthResult(resultCode, *finalResult);
        }
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
