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
#ifndef IAM_MOCK_RESOURCE_NODE_H
#define IAM_MOCK_RESOURCE_NODE_H

#include <memory>

#include <gmock/gmock.h>

#include "resource_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockResourceNode final : public ResourceNode, public std::enable_shared_from_this<MockResourceNode> {
public:
    MOCK_CONST_METHOD0(GetExecutorIndex, uint64_t());
    MOCK_CONST_METHOD0(GetOwnerDeviceId, std::string());
    MOCK_CONST_METHOD0(GetOwnerPid, uint32_t());
    MOCK_CONST_METHOD0(GetAuthType, AuthType());
    MOCK_CONST_METHOD0(GetExecutorRole, ExecutorRole());
    MOCK_CONST_METHOD0(GetExecutorMatcher, uint64_t());
    MOCK_CONST_METHOD0(GetExecutorSensorHint, uint64_t());
    MOCK_CONST_METHOD0(GetExecutorEsl, ExecutorSecureLevel());
    MOCK_CONST_METHOD0(GetExecutorPublicKey, std::vector<uint8_t>());

    MOCK_METHOD3(BeginExecute,
        int32_t(uint64_t scheduleId, const std::vector<uint8_t> &publicKey, const Attributes &command));
    MOCK_METHOD2(EndExecute, int32_t(uint64_t scheduleId, const Attributes &command));
    MOCK_METHOD1(SetProperty, int32_t(const Attributes &properties));
    MOCK_METHOD2(GetProperty, int32_t(const Attributes &condition, Attributes &values));
    MOCK_METHOD0(Detach, void());

    static std::shared_ptr<ResourceNode> CreateWithExecuteIndex(uint64_t executorId, bool detach = false)
    {
        using namespace testing;
        auto node = std::make_shared<MockResourceNode>();
        EXPECT_CALL(*node, GetExecutorIndex()).WillRepeatedly(Return(executorId));
        EXPECT_CALL(*node, GetAuthType()).WillRepeatedly(Return(PIN));
        EXPECT_CALL(*node, GetExecutorRole()).WillRepeatedly(Return(COLLECTOR));
        EXPECT_CALL(*node, GetExecutorMatcher()).WillRepeatedly(Return(0));
        EXPECT_CALL(*node, GetExecutorSensorHint()).WillRepeatedly(Return(0));
        EXPECT_CALL(*node, Detach()).Times(detach ? 1 : 0);
        return node;
    }

    static std::shared_ptr<ResourceNode> CreateWithExecuteIndex(uint64_t executorId, AuthType authType,
        ExecutorRole executorRole, ExecutorCallbackInterface &callback)
    {
        using namespace testing;
        auto node = std::make_shared<MockResourceNode>();
        std::vector<uint8_t> key;
        EXPECT_CALL(*node, GetExecutorIndex()).WillRepeatedly(Return(executorId));
        EXPECT_CALL(*node, GetAuthType()).WillRepeatedly(Return(authType));
        EXPECT_CALL(*node, GetExecutorRole()).WillRepeatedly(Return(executorRole));
        EXPECT_CALL(*node, GetExecutorMatcher()).WillRepeatedly(Return(0));
        EXPECT_CALL(*node, GetExecutorSensorHint()).WillRepeatedly(Return(0));
        EXPECT_CALL(*node, GetExecutorPublicKey()).WillRepeatedly(Return(key));
        EXPECT_CALL(*node, BeginExecute(_, _, _)).Times(AnyNumber());
        EXPECT_CALL(*node, EndExecute(_, _)).Times(AnyNumber());

        ON_CALL(*node, BeginExecute)
            .WillByDefault(
                [&callback](uint64_t scheduleId, const std::vector<uint8_t> &publicKey, const Attributes &command) {
                    return callback.OnBeginExecute(scheduleId, publicKey, command);
                });
        ON_CALL(*node, EndExecute).WillByDefault([&callback](uint64_t scheduleId, const Attributes &command) {
            return callback.OnEndExecute(scheduleId, command);
        });

        return node;
    }

    static std::shared_ptr<ResourceNode> CreateWithExecuteIndex(uint64_t executorId, AuthType authType,
        ExecutorRole executorRole)
    {
        using namespace testing;
        auto node = std::make_shared<MockResourceNode>();
        std::vector<uint8_t> key;
        EXPECT_CALL(*node, GetExecutorIndex()).WillRepeatedly(Return(executorId));
        EXPECT_CALL(*node, GetAuthType()).WillRepeatedly(Return(authType));
        EXPECT_CALL(*node, GetExecutorRole()).WillRepeatedly(Return(executorRole));
        EXPECT_CALL(*node, GetExecutorMatcher()).WillRepeatedly(Return(0));
        EXPECT_CALL(*node, GetExecutorSensorHint()).WillRepeatedly(Return(0));
        EXPECT_CALL(*node, GetExecutorPublicKey()).WillRepeatedly(Return(key));
        EXPECT_CALL(*node, BeginExecute(_, _, _)).Times(AnyNumber());
        EXPECT_CALL(*node, EndExecute(_, _)).Times(AnyNumber());
        return node;
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_RESOURCE_NODE_H