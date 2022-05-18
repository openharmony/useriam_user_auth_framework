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

#include "executor.h"

#include <sstream>

#include "co_auth_defines.h"
#include "executor_mgr.h"
#include "framework_executor_callback.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
const int32_t INVALID_EXECUTOR_ID = -1;

Executor::Executor(std::shared_ptr<IAuthExecutorHdi> executorHdi, uint16_t hdiId)
    : executorHdi_(executorHdi),
      hdiId_(hdiId)
{
    SetStr(INVALID_EXECUTOR_ID);
}

void Executor::OnHdiConnect()
{
    IAM_LOGI("%{public}s start", GetDescription());
    // register resource pool depends on hdi start, after hid connect re-register resource pool
    OnFrameworkReady();
}

void Executor::OnHdiDisconnect()
{
    IAM_LOGI("%{public}s start", GetDescription());
    executorHdi_ = nullptr;
}

void Executor::OnFrameworkReady()
{
    IAM_LOGI("%{public}s start", GetDescription());
    ExecutorInfo executorInfo = {};
    auto hdi = executorHdi_;
    if (hdi == nullptr) {
        IAM_LOGE("executorHdi_ is disconnected, skip framework ready process");
        return;
    }
    ResultCode ret = hdi->GetExecutorInfo(executorInfo);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("Get executor info failed");
        return;
    }
    SetStr(executorInfo.executorId);
    RegisterExecutorCallback(executorInfo);
}

void Executor::RegisterExecutorCallback(ExecutorInfo &executorInfo)
{
    IAM_LOGI("%{public}s start", GetDescription());
    auto combineResult = Common::CombineShortToInt(hdiId_, static_cast<uint16_t>(executorInfo.executorId));
    executorInfo.executorId = static_cast<int32_t>(combineResult);
    auto executorCallback = Common::MakeShared<FrameworkExecutorCallback>(shared_from_this());
    IF_FALSE_LOGE_AND_RETURN(executorCallback != nullptr);
    UserIAM::AuthResPool::ExecutorMgr::GetInstance().Register(executorInfo, executorCallback);
    IAM_LOGI(
        "register executor callback ok, executor id %{public}s", GET_MASKED_STRING(executorInfo.executorId).c_str());
}

void Executor::SetExecutorMessenger(const sptr<AuthResPool::IExecutorMessenger> &messenger)
{
    IAM_LOGI("%{public}s start", GetDescription());
    executorMessenger_ = messenger;
    return;
}

sptr<AuthResPool::IExecutorMessenger> Executor::GetExecutorMessenger()
{
    IAM_LOGI("%{public}s start", GetDescription());
    return executorMessenger_;
}

void Executor::AddCommand(std::shared_ptr<IAsyncCommand> command)
{
    IAM_LOGI("%{public}s start", GetDescription());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IF_FALSE_LOGE_AND_RETURN(command != nullptr);
    command2Respond_.insert(command);
}

void Executor::RemoveCommand(std::shared_ptr<IAsyncCommand> command)
{
    IAM_LOGI("%{public}s start", GetDescription());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    command2Respond_.erase(command);
}

void Executor::RespondCallbackOnDisconnect()
{
    IAM_LOGI("%{public}s start", GetDescription());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto it = command2Respond_.begin(); it != command2Respond_.end();) {
        auto cmdToProc = it;
        ++it;
        if (*cmdToProc == nullptr) {
            IAM_LOGE("cmdToProc is null");
            continue;
        }
        (*cmdToProc)->OnHdiDisconnect();
    }
    command2Respond_.clear();
    IAM_LOGI("success");
}

std::shared_ptr<IAuthExecutorHdi> Executor::GetExecutorHdi()
{
    return executorHdi_;
}

const char *Executor::GetDescription()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return str_.c_str();
}

void Executor::SetStr(const int32_t executorId)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::ostringstream ss;
    if (executorId == INVALID_EXECUTOR_ID) {
        ss << "Executor(hdiId:" << hdiId_ << ", executorId: not set)";
    } else {
        ss << "Executor(hdiId:" << hdiId_ << ", executorId:" << executorId << ")";
    }
    str_ = ss.str();
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
