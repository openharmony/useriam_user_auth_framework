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
#ifndef IAM_MOCK_RESOURCE_NODE_POOL_LISTENER_H
#define IAM_MOCK_RESOURCE_NODE_POOL_LISTENER_H

#include <gmock/gmock.h>

#include "iam_ptr.h"
#include "resource_node_pool.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockResourceNodePoolListener final : public ResourceNodePool::ResourceNodePoolListener {
public:
    MOCK_METHOD1(OnResourceNodePoolInsert, void(const std::shared_ptr<ResourceNode> &resource));
    MOCK_METHOD1(OnResourceNodePoolDelete, void(const std::shared_ptr<ResourceNode> &resource));
    MOCK_METHOD1(OnResourceNodePoolUpdate, void(const std::shared_ptr<ResourceNode> &resource));

    enum Action {
        INSERT,
        DELETE,
        UPDATE,
    };

    using Callback = std::function<void(Action action, const std::shared_ptr<ResourceNode> &resource)>;

    static std::shared_ptr<ResourceNodePool::ResourceNodePoolListener> Create(const Callback &callback)
    {
        using namespace testing;
        auto listener = Common::MakeShared<MockResourceNodePoolListener>();
        EXPECT_CALL(*listener, OnResourceNodePoolInsert).Times(AtLeast(0));
        ON_CALL(*listener, OnResourceNodePoolInsert)
            .WillByDefault([callback](const std::shared_ptr<ResourceNode> &resource) {
                if (callback != nullptr) {
                    return callback(INSERT, resource);
                }
            });
        EXPECT_CALL(*listener, OnResourceNodePoolDelete).Times(AtLeast(0));
        ON_CALL(*listener, OnResourceNodePoolDelete)
            .WillByDefault([callback](const std::shared_ptr<ResourceNode> &resource) {
                if (callback != nullptr) {
                    return callback(DELETE, resource);
                }
            });
        EXPECT_CALL(*listener, OnResourceNodePoolUpdate).Times(AtLeast(0));
        ON_CALL(*listener, OnResourceNodePoolUpdate)
            .WillByDefault([callback](const std::shared_ptr<ResourceNode> &resource) {
                if (callback != nullptr) {
                    return callback(UPDATE, resource);
                }
            });
        return listener;
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_RESOURCE_NODE_POOL_LISTENER_H