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

#ifndef EXCECUTOR_H
#define EXCECUTOR_H

#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include "iasync_command.h"
#include "iauth_executor_hdi.h"
#include "iexecute_callback.h"
#include "iexecutor_messenger.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class Executor : public std::enable_shared_from_this<Executor>, public NoCopyable {
public:
    Executor(std::shared_ptr<IAuthExecutorHdi> executorHdi, uint16_t hdiId);
    virtual ~Executor() = default;

    void OnHdiConnect();
    void OnHdiDisconnect();
    void OnFrameworkReady();
    void SetExecutorMessenger(const sptr<AuthResPool::IExecutorMessenger> &messenger);
    sptr<AuthResPool::IExecutorMessenger> GetExecutorMessenger();
    void AddCommand(std::shared_ptr<IAsyncCommand> command);
    void RemoveCommand(std::shared_ptr<IAsyncCommand> command);
    std::shared_ptr<IAuthExecutorHdi> GetExecutorHdi();
    const char *GetDescription();

private:
    void RegisterExecutorCallback(ExecutorInfo &executorInfo);
    void RespondCallbackOnDisconnect();
    void SetStr(const int32_t executorId);
    sptr<AuthResPool::IExecutorMessenger> executorMessenger_;
    std::recursive_mutex mutex_;
    std::set<std::shared_ptr<IAsyncCommand>> command2Respond_;
    std::shared_ptr<IAuthExecutorHdi> executorHdi_;
    std::string str_;
    uint16_t hdiId_;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS

#endif // EXCECUTOR_H