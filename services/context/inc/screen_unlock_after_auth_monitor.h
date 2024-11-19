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

#ifndef SCREEN_UNLOCK_AFTER_AUTH_MONITOR_H
#define SCREEN_UNLOCK_AFTER_AUTH_MONITOR_H

#include <mutex>
#include <optional>
#include <vector>

#include "nocopyable.h"

#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using time_point = std::chrono::steady_clock::time_point;

struct AuthSuccessData {
    int32_t userId;
    int32_t authType;
    std::string authSuccessTime;
};

class ScreenUnlockAfterAuthMonitor : public NoCopyable {
public:
    static ScreenUnlockAfterAuthMonitor &GetInstance();

    void OnScreenUnlocked();
    void OnAuthSuccess(const AuthSuccessData &data);
    void OnTimeOut();

private:
    ScreenUnlockAfterAuthMonitor() = default;
    ~ScreenUnlockAfterAuthMonitor() override = default;

    std::recursive_mutex mutex_;
    std::optional<time_point> screenUnlockedTime_ = std::nullopt;
    std::optional<int32_t> timerId_ = std::nullopt;
    std::vector<AuthSuccessData> authSuccessData_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // SCREEN_UNLOCK_AFTER_AUTH_MONITOR_H