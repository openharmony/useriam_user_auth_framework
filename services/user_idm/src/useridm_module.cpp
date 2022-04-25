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

#include "useridm_module.h"
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
bool UserIDMModule::InsertChallenge(uint64_t challenge)
{
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    USERIDM_HILOGI(MODULE_SERVICE, "Data module InsertChallenge start");

    challengeAndScheduleId_.first = challenge;

    return true;
}

bool UserIDMModule::InsertScheduleId(uint64_t scheduleId)
{
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    USERIDM_HILOGI(MODULE_SERVICE, "Data module InsertScheduleId start");

    challengeAndScheduleId_.second = scheduleId;

    return true;
}

void UserIDMModule::DeleteChallenge()
{
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    USERIDM_HILOGI(MODULE_SERVICE, "Data module DeleteChallenge start");

    challengeAndScheduleId_.first = 0;
}

void UserIDMModule::DeleteSessionId()
{
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    USERIDM_HILOGI(MODULE_SERVICE, "Data module DeleteSessionId start");

    challengeAndScheduleId_.second = 0;
}

void UserIDMModule::CleanData()
{
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    USERIDM_HILOGI(MODULE_SERVICE, "Data module CleanData start");

    challengeAndScheduleId_.first = 0;
    challengeAndScheduleId_.second = 0;
}

bool UserIDMModule::CheckChallenge(uint64_t& challenge)
{
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    USERIDM_HILOGI(MODULE_SERVICE, "Data module CheckChallenge start");
    if (challengeAndScheduleId_.first == 0) {
        USERIDM_HILOGE(MODULE_SERVICE, "no session num");
        return false;
    }
    challenge = challengeAndScheduleId_.first;
    return true;
}

bool UserIDMModule::CheckScheduleIdIsActive(uint64_t& scheduleId)
{
    std::lock_guard<std::mutex> idmMutexGuard(mutex_);
    USERIDM_HILOGI(MODULE_SERVICE, "Data module CheckScheduleIdIsActive start");
    bool res = false;

    if (challengeAndScheduleId_.second == 0) {
        USERIDM_HILOGE(MODULE_SERVICE, "no session num");
    } else {
        res = true;
        scheduleId = challengeAndScheduleId_.second;
    }

    return res;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS