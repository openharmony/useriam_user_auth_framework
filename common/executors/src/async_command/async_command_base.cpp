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

#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
AsyncCommandBase::AsyncCommandBase(std::string type, uint64_t scheduleId, std::shared_ptr<Executor> executor)
    : scheduleId_(scheduleId),
      executor_(executor),
      commandId_(GenerateCommandId())
{
    std::ostringstream ss;
    ss << "Command(type:" << type << ", id:" << commandId_ << ", scheduleId:" << GET_MASKED_STRING(scheduleId_) << ")";
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
    IF_FALSE_LOGE_AND_RETURN_VAL(executor_ != nullptr, ResultCode::GENERAL_ERROR);

    executor_->AddCommand(shared_from_this());
    ResultCode ret = SendRequest();
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("send request failed");
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
    OnResultInner(result, extraInfo);
    EndProcess();
}

void AsyncCommandBase::EndProcess()
{
    IAM_LOGI("%{public}s end process", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(executor_ != nullptr);
    executor_->RemoveCommand(shared_from_this());
}

const char *AsyncCommandBase::GetDescription()
{
    return description_.c_str();
}

uint32_t AsyncCommandBase::GenerateCommandId()
{
    static std::mutex mutex;
    static uint32_t commandId = 0;
    std::lock_guard<std::mutex> guard(mutex);
    ++commandId;
    return commandId;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
