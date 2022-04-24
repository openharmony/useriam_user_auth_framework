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

#ifndef USERIDM_MODULE_H
#define USERIDM_MODULE_H

#include <mutex>

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMModule {
public:
    bool InsertChallenge(uint64_t challenge);
    bool InsertScheduleId(uint64_t scheduleId);
    void DeleteChallenge();
    void DeleteSessionId();
    void CleanData();
    bool CheckChallenge(uint64_t& challenge);
    bool CheckScheduleIdIsActive(uint64_t& scheduleId);

private:
    std::pair<uint64_t, uint64_t> challengeAndScheduleId_;
    std::mutex mutex_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
#endif // USERIDM_MODULE_H