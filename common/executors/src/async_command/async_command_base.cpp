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

#include "async_command_base.h"

#include <atomic>
#include <cstdint>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "iam_check.h"
#include "iam_defines.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "framework_types.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIam {
namespace UserAuth {
AsyncCommandBase::AsyncCommandBase(std::string type, uint64_t scheduleId, std::weak_ptr<Executor> executor,
    std::shared_ptr<ExecutorMessenger> executorMessenger)
    : scheduleId_(scheduleId),
      executor_(executor),
      executorMessenger_(executorMessenger)
{
    auto commandId = GenerateCommandId();
    std::ostringstream ss;
    ss << "Command(type:" << type << ", id:" << commandId << ", scheduleId:" << GET_MASKED_STRING(scheduleId_) << ")";
    description_ = ss.str();
}

void AsyncCommandBase::OnHdiDisconnect()
{
    IAM_LOGI("driver disconnect, %{public}s end process", GetDescription());
    // Need new result code: hal invalid
    OnResult(ResultCode::GENERAL_ERROR);
}

ResultCode AsyncCommandBase::StartProcess()
{
    IAM_LOGI("%{public}s start process", GetDescription());
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("%{public}s executor has been released, start process fail", GetDescription());
        return ResultCode::GENERAL_ERROR;
    }
    executor->AddCommand(shared_from_this());
    ResultCode ret = SendRequest();
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s send request failed", GetDescription());
        EndProcess();
        return ret;
    }
    return ResultCode::SUCCESS;
}

void AsyncCommandBase::OnResult(ResultCode result)
{
    std::vector<uint8_t> extraInfo;
    OnResult(result, extraInfo);
}

void AsyncCommandBase::OnResult(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (isFinished_) {
        IAM_LOGE("command is finished, invocation of OnResult is invalid");
        return;
    }
    isFinished_ = true;
    OnResultInner(result, extraInfo);
    EndProcess();
}

void AsyncCommandBase::OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (isFinished_) {
        IAM_LOGE("command is finished, invocation of OnAcquireInfo is invalid");
        return;
    }
    OnAcquireInfoInner(acquire, extraInfo);
}

int32_t AsyncCommandBase::GetAuthType()
{
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("%{public}s executor has been released, get executor type fail", GetDescription());
        return INVALID_AUTH_TYPE;
    }
    return executor->GetAuthType();
}

void AsyncCommandBase::EndProcess()
{
    IAM_LOGI("%{public}s end process", GetDescription());
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGI(
            "%{public}s executor has been released, command has been removed, no need remove again", GetDescription());
        return;
    }
    executor->RemoveCommand(shared_from_this());
}

const char *AsyncCommandBase::GetDescription()
{
    return description_.c_str();
}

uint32_t AsyncCommandBase::GenerateCommandId()
{
    std::atomic<uint32_t> commandId = 0;
    // commandId is only used in log, uint32 overflow or duplicate is ok
    return ++commandId;
}

std::shared_ptr<IAuthExecutorHdi> AsyncCommandBase::GetExecutorHdi()
{
    auto executor = executor_.lock();
    if (executor == nullptr) {
        IAM_LOGE("%{public}s executor has been released, get executor hdi fail", GetDescription());
        return nullptr;
    }
    return executor->GetExecutorHdi();
}

int32_t AsyncCommandBase::MessengerSendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcType,
    ExecutorRole dstType, std::shared_ptr<AuthMessage> msg)
{
    auto messenger = executorMessenger_;
    IF_FALSE_LOGE_AND_RETURN_VAL(messenger != nullptr, USERAUTH_ERROR);
    return messenger->SendData(scheduleId, transNum, srcType, dstType, msg);
}

int32_t AsyncCommandBase::MessengerFinish(uint64_t scheduleId, ExecutorRole srcType, int32_t resultCode,
    std::shared_ptr<Attributes> finalResult)
{
    auto messenger = executorMessenger_;
    IF_FALSE_LOGE_AND_RETURN_VAL(messenger != nullptr, USERAUTH_ERROR);
    int32_t ret = messenger->Finish(scheduleId, srcType, resultCode, *finalResult);
    executorMessenger_ = nullptr;
    return ret;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
