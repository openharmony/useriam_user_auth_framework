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

#ifndef FRAMEWORK_EXECUTOR_CALLBACK_H
#define FRAMEWORK_EXECUTOR_CALLBACK_H

#include <cstdint>
#include <string>

#include "nocopyable.h"

#include "attributes.h"
#include "co_auth_client_callback.h"
#include "executor.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class FrameworkExecutorCallback : public ExecutorRegisterCallback, public NoCopyable {
public:
    explicit FrameworkExecutorCallback(std::weak_ptr<Executor> executor);
    ~FrameworkExecutorCallback() override = default;

    void OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger, const std::vector<uint8_t> &publicKey,
        const std::vector<uint64_t> &templateIds) override;

    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &commandAttrs) override;
    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs) override;
    int32_t OnSetProperty(const Attributes &properties) override;

    int32_t OnGetProperty(const Attributes &conditions, Attributes &results) override;

private:
    static uint32_t GenerateExecutorCallbackId();
    ResultCode OnBeginExecuteInner(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
        const Attributes &commandAttrs);
    ResultCode OnEndExecuteInner(uint64_t scheduleId, const Attributes &consumerAttr);
    ResultCode OnSetPropertyInner(const Attributes &properties);
    ResultCode OnGetPropertyInner(std::shared_ptr<Attributes> conditions,
        std::shared_ptr<Attributes> values);
    ResultCode ProcessEnrollCommand(uint64_t scheduleId, const Attributes &properties);
    ResultCode ProcessAuthCommand(uint64_t scheduleId, const Attributes &properties);
    ResultCode ProcessIdentifyCommand(uint64_t scheduleId, const Attributes &properties);
    ResultCode ProcessCancelCommand(uint64_t scheduleId);
    ResultCode ProcessDeleteTemplateCommand(const Attributes &properties);
    ResultCode ProcessCustomCommand(const Attributes &properties);
    ResultCode ProcessGetTemplateCommand(std::shared_ptr<Attributes> conditions,
        std::shared_ptr<Attributes> values);
    const char *GetDescription();
    std::shared_ptr<ExecutorMessenger> executorMessenger_;
    std::weak_ptr<Executor> executor_;
    std::string description_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // FRAMEWORK_EXECUTOR_CALLBACK_H