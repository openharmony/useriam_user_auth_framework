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

#ifndef MOCK_EXECUTOR_H
#define MOCK_EXECUTOR_H

#include "gmock/gmock.h"

#include "executor.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockExecutor : public Executor {
public:
    virtual ~MockExecutor() = default;

    MOCK_METHOD0(OnHdiConnect, void());
    MOCK_METHOD0(OnHdiDisconnect, void());
    MOCK_METHOD0(OnFrameworkReady, void());
    MOCK_METHOD1(AddCommand, void(std::shared_ptr<IAsyncCommand> command));
    MOCK_METHOD1(RemoveCommand, void(std::shared_ptr<IAsyncCommand> command));
    MOCK_METHOD0(GetExecutorHdi, std::shared_ptr<IAuthExecutorHdi>());
    MOCK_METHOD0(GetDescription, const char *());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_EXECUTOR_H