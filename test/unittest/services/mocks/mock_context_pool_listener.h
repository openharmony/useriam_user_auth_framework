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
#ifndef IAM_MOCK_CONTEXT_POOL_LISTENER_H
#define IAM_MOCK_CONTEXT_POOL_LISTENER_H

#include <gmock/gmock.h>

#include "context_pool.h"
#include "iam_ptr.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockContextPoolListener final : public ContextPool::ContextPoolListener {
public:
    MOCK_METHOD1(OnContextPoolInsert, void(const std::shared_ptr<Context> &context));
    MOCK_METHOD1(OnContextPoolDelete, void(const std::shared_ptr<Context> &context));

    enum Action {
        INSERT,
        DELETE,
    };

    using Callback = std::function<void(Action action, const std::shared_ptr<Context> &context)>;

    static std::shared_ptr<ContextPool::ContextPoolListener> Create(const Callback &callback)
    {
        using namespace testing;
        auto listener = Common::MakeShared<MockContextPoolListener>();
        EXPECT_CALL(*listener, OnContextPoolInsert).Times(AtLeast(0));
        ON_CALL(*listener, OnContextPoolInsert).WillByDefault([callback](const std::shared_ptr<Context> &context) {
            if (callback != nullptr) {
                return callback(INSERT, context);
            }
        });
        EXPECT_CALL(*listener, OnContextPoolDelete).Times(AtLeast(0));
        ON_CALL(*listener, OnContextPoolDelete).WillByDefault([callback](const std::shared_ptr<Context> &context) {
            if (callback != nullptr) {
                return callback(DELETE, context);
            }
        });
        return listener;
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_CONTEXT_POOL_LISTENER_H