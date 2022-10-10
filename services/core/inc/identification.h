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

#ifndef IAM_IDENTIFICATION_H
#define IAM_IDENTIFICATION_H

#include <cstdint>
#include <memory>

#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Identification {
public:
    struct IdentifyResultInfo {
        int32_t result;
        int32_t userId;
        std::vector<uint8_t> token;
    };
    virtual ~Identification() = default;

    virtual void SetExecutor(uint32_t executorIndex) = 0;
    virtual void SetChallenge(const std::vector<uint8_t> &challenge) = 0;
    virtual void SetAccessTokenId(uint32_t tokenId) = 0;

    virtual bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback) = 0;
    virtual bool Update(const std::vector<uint8_t> &scheduleResult, IdentifyResultInfo &resultInfo) = 0;
    virtual bool Cancel() = 0;
    virtual int32_t GetLatestError() const = 0;

protected:
    virtual void SetLatestError(int32_t error) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_IDENTIFICATION_H