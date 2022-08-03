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

#ifndef MOCK_IASYNC_COMMAND_H
#define MOCK_IASYNC_COMMAND_H

#include "gmock/gmock.h"

#include "iasync_command.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIAsyncCommand : public IAsyncCommand {
public:
    virtual ~MockIAsyncCommand() = default;

    MOCK_METHOD0(OnHdiDisconnect, void());
    MOCK_METHOD0(StartProcess, ResultCode());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_IASYNC_COMMAND_H