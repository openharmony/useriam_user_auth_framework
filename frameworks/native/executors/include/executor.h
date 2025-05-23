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

#include "nocopyable.h"

#include "co_auth_client_callback.h"
#include "executor_mgr_wrapper.h"
#include "iasync_command.h"
#include "iam_defines.h"
#include "iam_executor_iauth_executor_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Executor : public std::enable_shared_from_this<Executor>, public NoCopyable {
public:
    Executor(std::shared_ptr<ExecutorMgrWrapper> executorMgrWrapper, std::shared_ptr<IAuthExecutorHdi> executorHdi,
        uint16_t hdiId);
    ~Executor() override = default;

    void OnHdiDisconnect();
    void Register();
    void AddCommand(std::shared_ptr<IAsyncCommand> command);
    void RemoveCommand(std::shared_ptr<IAsyncCommand> command);
    void SetExecutorIndex(uint64_t executorIndex);
    std::shared_ptr<IAuthExecutorHdi> GetExecutorHdi();
    const char *GetDescription();
    int32_t GetAuthType() const;
    int32_t GetExecutorRole() const;

private:
    void RegisterExecutorCallback(ExecutorInfo &executorInfo);
    void UnregisterExecutorCallback();
    void RespondCallbackOnDisconnect();
    std::recursive_mutex registerMutex_;
    std::recursive_mutex mutex_;
    std::shared_ptr<ExecutorRegisterCallback> executorCallback_ {nullptr};
    std::set<std::shared_ptr<IAsyncCommand>> command2Respond_;
    std::shared_ptr<ExecutorMgrWrapper> executorMgrWrapper_ {nullptr};
    std::shared_ptr<IAuthExecutorHdi> executorHdi_ {nullptr};
    std::string description_;
    uint16_t hdiId_ = 0;
    int32_t authType_ = INVALID_AUTH_TYPE;
    int32_t executorRole_ = -1;
    std::optional<uint64_t> executorIndex_ = std::nullopt;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // EXCECUTOR_H