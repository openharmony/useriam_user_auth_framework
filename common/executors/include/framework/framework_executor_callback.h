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

#include "auth_attributes.h"
#include "auth_executor.h"
#include "co_auth_defines.h"
#include "executor.h"
#include "executor_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using namespace AuthResPool;
enum ScheduleMode {
    SCHEDULE_MODE_ENROLL = 0,
    SCHEDULE_MODE_AUTH = 1,
};

class FrameworkExecutorCallback : public ExecutorCallback, public NoCopyable {
public:
    explicit FrameworkExecutorCallback(std::weak_ptr<Executor> executor);
    ~FrameworkExecutorCallback() override = default;

    int32_t OnBeginExecute(
        uint64_t scheduleId, std::vector<uint8_t> &publicKey, std::shared_ptr<AuthAttributes> commandAttrs) override;
    int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr) override;
    int32_t OnSetProperty(std::shared_ptr<AuthAttributes> properties) override;
    void OnMessengerReady(const sptr<IExecutorMessenger> &messenger, std::vector<uint8_t> &publicKey,
        std::vector<uint64_t> &templateIds) override;
    int32_t OnGetProperty(std::shared_ptr<AuthAttributes> conditions, std::shared_ptr<AuthAttributes> values) override;

private:
    static uint32_t GenerateExecutorCallbackId();
    ResultCode OnBeginExecuteInner(
        uint64_t scheduleId, std::vector<uint8_t> &publicKey, std::shared_ptr<AuthAttributes> commandAttrs);
    ResultCode OnEndExecuteInner(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr);
    ResultCode OnSetPropertyInner(std::shared_ptr<AuthAttributes> properties);
    ResultCode OnGetPropertyInner(std::shared_ptr<AuthAttributes> conditions, std::shared_ptr<AuthAttributes> values);
    ResultCode ProcessEnrollCommand(uint64_t scheduleId, std::shared_ptr<AuthAttributes> properties);
    ResultCode ProcessAuthCommand(uint64_t scheduleId, std::shared_ptr<AuthAttributes> properties);
    ResultCode ProcessIdentifyCommand(uint64_t scheduleId, std::shared_ptr<AuthAttributes> properties);
    ResultCode ProcessCancelCommand(uint64_t scheduleId);
    ResultCode ProcessDeleteTemplateCommand(std::shared_ptr<AuthAttributes> properties);
    ResultCode ProcessCustomCommand(std::shared_ptr<AuthAttributes> properties);
    ResultCode ProcessGetTemplateCommand(
        std::shared_ptr<AuthAttributes> conditions, std::shared_ptr<AuthAttributes> values);
    const char *GetDescription();
    sptr<IExecutorMessenger> executorMessenger_;
    std::weak_ptr<Executor> executor_;
    std::string description_;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS

#endif // FRAMEWORK_EXECUTOR_CALLBACK_H