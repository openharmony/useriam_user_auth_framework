/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "screen_unlock_after_auth_monitor.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "relative_timer.h"
#include "hisysevent_adapter.h"

#define LOG_TAG "USER_AUTH_SA"

using namespace std::chrono;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ScreenUnlockAfterAuthMonitor &ScreenUnlockAfterAuthMonitor::GetInstance()
{
    static ScreenUnlockAfterAuthMonitor instance;
    return instance;
}

void ScreenUnlockAfterAuthMonitor::OnScreenUnlocked()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    authSuccessData_.clear();
    screenUnlockedTime_ = steady_clock::now();
    if (timerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(timerId_.value());
        timerId_ = std::nullopt;
    }
}

void ScreenUnlockAfterAuthMonitor::OnAuthSuccess(const AuthSuccessData &data)
{
    const int32_t SCREEN_UNLOCK_BEFORE_AUTH_TIME_LIMIT = 3000; // 3s
    const int32_t SCREEN_UNLOCK_AFTER_AUTH_TIME_LIMIT = 3000; // 3s

    if (data.authType == FACE) {
        return;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);

    if (screenUnlockedTime_.has_value() &&
        (steady_clock::now() - screenUnlockedTime_.value() < milliseconds(SCREEN_UNLOCK_BEFORE_AUTH_TIME_LIMIT))) {
        IAM_LOGI("screen unlocked before auth success, ignore");
        return;
    }

    authSuccessData_.push_back(data);
    IAM_LOGI("record auth success userId: %{public}d, authType: %{public}d", data.userId, data.authType);
    if (!timerId_.has_value()) {
        timerId_ = RelativeTimer::GetInstance().Register([this]() { OnTimeOut(); },
            SCREEN_UNLOCK_AFTER_AUTH_TIME_LIMIT);
    }
}

void ScreenUnlockAfterAuthMonitor::OnTimeOut()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (authSuccessData_.empty()) {
        IAM_LOGI("authSuccessData_ is empty");
        return;
    }

    IAM_LOGE("screen not unlocked after auth success, auth success num %{public}zu", authSuccessData_.size());
    for (const auto &data : authSuccessData_) {
        ReportAuthSuccessNoUnlockTrace trace = {
            .userId = data.userId,
            .authType = data.authType,
            .receiveResultTime = data.authSuccessTime,
        };
        ReportAuthSuccessNoUnlock(trace);
    }
    authSuccessData_.clear();
    timerId_ = std::nullopt;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS