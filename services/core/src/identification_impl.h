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

#ifndef IAM_IDENTIFICATION_IMPL_H
#define IAM_IDENTIFICATION_IMPL_H

#include <cstdint>
#include <memory>

#include "identification.h"
#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdentificationImpl final : public Identification, public NoCopyable {
public:
    IdentificationImpl(uint64_t contextId, AuthType authType);
    ~IdentificationImpl() override;

    void SetExecutor(uint32_t executorIndex) override;
    void SetChallenge(const std::vector<uint8_t> &challenge) override;
    void SetAccessTokenId(uint32_t tokenId) override;

    bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback) override;
    bool Update(const std::vector<uint8_t> &scheduleResult, IdentifyResultInfo &resultInfo) override;
    bool Cancel() override;
    int32_t GetLatestError() const override;

protected:
    void SetLatestError(int32_t error) override;

private:
    uint64_t contextId_;
    AuthType authType_;

    uint32_t executorIndex_ {0};
    std::vector<uint8_t> challenge_ {};
    uint32_t tokenId_ {0};

    bool running_ {false};
    int32_t latestError_ = ResultCode::GENERAL_ERROR;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_IDENTIFICATION_IMPL_H