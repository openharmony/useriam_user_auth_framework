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
#ifndef IAM_MOCK_CONTEXT_H
#define IAM_MOCK_CONTEXT_H

#include <memory>

#include <gmock/gmock.h>

#include "context.h"
#include "iam_ptr.h"
#include "mock_schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockContextCallback : public ContextCallback {
public:
    virtual ~MockContextCallback() = default;
    MOCK_CONST_METHOD3(onAcquireInfo,
        void(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg));
    MOCK_CONST_METHOD2(OnResult, void(int32_t resultCode, const std::shared_ptr<Attributes> &finalResult));
};

class MockContext final : public Context {
public:
    MOCK_METHOD0(Start, bool());
    MOCK_METHOD0(Stop, bool());
    MOCK_METHOD1(SetContextStopCallback, void(ContextStopCallback callback));
    MOCK_CONST_METHOD0(GetContextId, uint64_t());
    MOCK_CONST_METHOD0(GetContextType, ContextType());
    MOCK_CONST_METHOD1(GetScheduleNode, std::shared_ptr<ScheduleNode>(uint64_t scheduleId));

    static std::shared_ptr<Context> CreateWithContextId(uint64_t contextId)
    {
        using namespace testing;
        auto context = UserIAM::Common::MakeShared<MockContext>();
        EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(contextId));
        return context;
    }

    static std::shared_ptr<Context> CreateContextWithScheduleNode(uint64_t contextId, std::set<uint64_t> scheduleIdList)
    {
        using namespace testing;
        auto context = UserIAM::Common::MakeShared<MockContext>();
        EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(contextId));
        EXPECT_CALL(*context, GetScheduleNode(_)).Times(AnyNumber());

        ON_CALL(*context, GetScheduleNode)
            .WillByDefault([scheduleIdList](uint64_t id) -> std::shared_ptr<ScheduleNode> {
                auto iter = scheduleIdList.find(id);
                if (iter != scheduleIdList.end()) {
                    return MockScheduleNode::CreateWithScheduleId(id);
                }
                return nullptr;
            });
        return context;
    }

    static std::shared_ptr<Context> CreateContextWithScheduleNode(uint64_t contextId,
        const std::set<std::shared_ptr<ScheduleNode>> &scheduleIdList)
    {
        using namespace testing;
        auto context = UserIAM::Common::MakeShared<MockContext>();
        EXPECT_CALL(*context, GetContextId()).WillRepeatedly(Return(contextId));
        EXPECT_CALL(*context, GetScheduleNode(_)).Times(AnyNumber());

        ON_CALL(*context, GetScheduleNode)
            .WillByDefault([scheduleIdList](uint64_t id) -> std::shared_ptr<ScheduleNode> {
                for (auto const &node : scheduleIdList) {
                    if (node->GetScheduleId() == id) {
                        return node;
                    }
                }
                return nullptr;
            });
        return context;
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_CONTEXT_H