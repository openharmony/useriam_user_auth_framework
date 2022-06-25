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
#ifndef IAM_MOCK_SCHEDULE_NODE_H
#define IAM_MOCK_SCHEDULE_NODE_H

#include <memory>

#include <gmock/gmock.h>

#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockScheduleNode final : public ScheduleNode {
public:
    MOCK_CONST_METHOD0(GetScheduleId, uint64_t());
    MOCK_CONST_METHOD0(GetContextId, uint64_t());
    MOCK_CONST_METHOD0(GetAuthType, AuthType());
    MOCK_CONST_METHOD0(GetExecutorMatcher, uint64_t());
    MOCK_CONST_METHOD0(GetScheduleMode, ScheduleMode());
    MOCK_CONST_METHOD0(GetCollectorExecutor, std::weak_ptr<ResourceNode>());
    MOCK_CONST_METHOD0(GetVerifyExecutor, std::weak_ptr<ResourceNode>());
    MOCK_CONST_METHOD0(GetTemplateIdList, std::optional<std::vector<uint64_t>>());
    MOCK_CONST_METHOD0(GetCurrentScheduleState, State());

    MOCK_METHOD1(RegisterScheduleCallback, bool(const std::shared_ptr<ScheduleNodeCallback> &callback));
    MOCK_METHOD1(SetExpiredTime, bool(uint32_t ms));
    MOCK_METHOD0(StartSchedule, bool());
    MOCK_METHOD0(StopSchedule, bool());
    MOCK_METHOD4(ContinueSchedule,
        bool(ExecutorRole srcRole, ExecutorRole dstRole, uint64_t transNum, const std::vector<uint8_t> &msg));
    MOCK_METHOD2(ContinueSchedule, bool(ResultCode resultCode, const std::shared_ptr<Attributes> &finalResult));

    static std::shared_ptr<MockScheduleNode> CreateWithScheduleId(uint64_t scheduleId)
    {
        using namespace testing;
        auto node = std::make_shared<MockScheduleNode>();
        EXPECT_CALL(*node, GetScheduleId()).WillRepeatedly(Return(scheduleId));
        return node;
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_SCHEDULE_NODE_H