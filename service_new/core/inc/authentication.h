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

#ifndef IAM_AUTHENTICATION_H
#define IAM_AUTHENTICATION_H

#include <cstdint>
#include <memory>

#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Authentication {
public:
    struct AuthResultInfo {
        uint32_t result;
        int32_t freezingTime;
        int32_t remainTimes;
        std::vector<uint8_t> token;
    };
    virtual ~Authentication() = default;

    virtual void SetExecutor(uint32_t executorIndex) = 0;
    virtual void SetChallenge(const std::vector<uint8_t> &challenge) = 0;
    virtual void SetCallingUid(uint32_t uid) = 0;

    virtual bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback) = 0;
    virtual bool Update(const std::vector<uint8_t> &scheduleResult, AuthResultInfo &resultInfo) = 0;
    virtual bool Cancel() = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_AUTHENTICATION_H