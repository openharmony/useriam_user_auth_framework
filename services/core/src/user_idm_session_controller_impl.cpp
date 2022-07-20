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

#include "user_idm_session_controller_impl.h"

#include <optional>

#include "hdi_wrapper.h"
#include "iam_logger.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

bool UserIdmSessionControllerImpl::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!map_.empty()) {
        IAM_LOGW("old session is not closed");
    }

    int32_t ret = hdi->OpenSession(userId, challenge);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("failed to open session, error code : %{public}d", ret);
        return false;
    }
    map_[userId] = challenge;
    return true;
}

bool UserIdmSessionControllerImpl::CloseSession(int32_t userId)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = hdi->CloseSession(userId);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("failed to close session, error code : %{public}d", ret);
        return false;
    }

    map_.erase(userId);
    return true;
}

bool UserIdmSessionControllerImpl::CloseSession(const std::vector<uint8_t> &challenge)
{
    std::optional<int32_t> userId;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &[key, value] : map_) {
            if (value == challenge) {
                userId = key;
                break;
            }
        }
    }

    if (userId.has_value()) {
        return CloseSession(userId.value());
    }

    return false;
}

bool UserIdmSessionControllerImpl::IsSessionOpened(int32_t userId) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return map_.find(userId) != map_.end();
}

bool UserIdmSessionControllerImpl::IsSessionOpened(const std::vector<uint8_t> &challenge) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &[key, value] : map_) {
        if (value == challenge) {
            return true;
        }
    }

    return false;
}

bool UserIdmSessionControllerImpl::ForceReset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    map_.clear();
    return true;
}

UserIdmSessionController::SessionMap UserIdmSessionControllerImpl::GetOpenedSessions() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return map_;
}

UserIdmSessionController &UserIdmSessionController::Instance()
{
    return UserIdmSessionControllerImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS