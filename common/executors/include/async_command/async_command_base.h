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

#ifndef ASYNC_COMMAND_BASE_H
#define ASYNC_COMMAND_BASE_H

#include <mutex>

#include "nocopyable.h"

#include "co_auth_defines.h"
#include "executor.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class AsyncCommandBase : public std::enable_shared_from_this<AsyncCommandBase>,
                         public IAsyncCommand,
                         public IExecuteCallback,
                         public NoCopyable {
public:
    AsyncCommandBase(std::string type, uint64_t scheduleId, std::shared_ptr<Executor> executor);
    ~AsyncCommandBase() override = default;

    void OnHdiDisconnect() override;
    ResultCode StartProcess() override;
    void OnResult(ResultCode result) override;
    void OnResult(ResultCode result, const std::vector<uint8_t> &extraInfo) override;
    void OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo) override = 0;

protected:
    static uint32_t GenerateCommandId();
    virtual ResultCode SendRequest() = 0;
    virtual void OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo) = 0;
    const char *GetDescription();
    uint64_t scheduleId_;
    std::shared_ptr<Executor> executor_;
    uint32_t commandId_;

private:
    void EndProcess();
    std::string description_;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS

#endif // ASYNC_COMMAND_BASE_H