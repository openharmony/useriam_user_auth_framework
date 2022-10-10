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

#ifndef IAM_ENROLLMENT_IMPL_H
#define IAM_ENROLLMENT_IMPL_H

#include <cstdint>
#include <memory>

#include "credential_info.h"
#include "enrollment.h"
#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EnrollmentImpl final : public Enrollment, public NoCopyable {
public:
    EnrollmentImpl(int32_t userId, AuthType authType);
    ~EnrollmentImpl() override;

    void SetExecutorSensorHint(uint32_t executorSensorHint) override;
    void SetAuthToken(const std::vector<uint8_t> &authToken) override;
    void SetAccessTokenId(uint32_t tokenId) override;
    void SetPinSubType(PinSubType pinSubType) override;

    bool Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
        std::shared_ptr<ScheduleNodeCallback> callback) override;
    bool Update(const std::vector<uint8_t> &scheduleResult, uint64_t &credentialId,
        std::shared_ptr<CredentialInfo> &info, std::vector<uint8_t> &rootSecret) override;
    bool Cancel() override;
    int32_t GetLatestError() const override;

protected:
    void SetLatestError(int32_t error) override;

private:
    int32_t userId_;
    AuthType authType_;
    std::vector<uint8_t> authToken_;

    uint32_t executorSensorHint_ {0};
    uint32_t tokenId_ {0};
    PinSubType pinSubType_ {PinSubType::PIN_MAX};
    bool running_ {false};
    int32_t latestError_ = ResultCode::GENERAL_ERROR;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_ENROLLMENT_IMPL_H