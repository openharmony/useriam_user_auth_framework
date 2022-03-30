
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "thread_groups.h"

#include <sstream>
#include <sys/prctl.h>

#include "iam_logger.h"
#include "thread_pool.h"

#define LOG_LABEL LABEL_IAM_UTILS

namespace OHOS {
namespace UserIAM {
namespace Utils {
using namespace OHOS;

static constexpr uint32_t THREAD_NUM_KEEP = 5;
static constexpr uint32_t THREAD_NUM_SINGLE = 1;

ThreadGroups::ThreadGroups() = default;
ThreadGroups::~ThreadGroups() = default;

bool ThreadGroups::CreateThreadGroup(const std::string &name, uint32_t threadNum)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto result = pools_.try_emplace(name, frees_, name, threadNum);
    if (!result.second) {
        IAM_LOGE("CreateThreadGroup %{public}s failed", name.c_str());
        return false;
    }
    return true;
}

bool ThreadGroups::DestroyThreadGroup(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = pools_.find(name);
    if (iter == pools_.end()) {
        IAM_LOGE("DestroyThreadGroup %{public}s failed for no such name", name.c_str());
        return false;
    }
    auto &group = iter->second;
    group.ReleaseAllTaskThread();
    pools_.erase(iter);
    IAM_LOGI("DestroyThreadGroup %{public}s success", name.c_str());
    return true;
}

bool ThreadGroups::RetainTaskThread(const std::string &name, uint64_t transaction, uint32_t maxTaskNum)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = pools_.find(name);
    if (iter == pools_.end()) {
        IAM_LOGE("RetainTaskThread %{public}s failed for no such name", name.c_str());
        return false;
    }
    if (transaction == 0) {
        IAM_LOGE("RetainTaskThread %{public}s failed for invalid transaction", name.c_str());
        return false;
    }
    auto &group = iter->second;
    return group.RetainTaskThread(transaction, maxTaskNum);
}

bool ThreadGroups::ReleaseTaskThread(const std::string &name, uint64_t transaction)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = pools_.find(name);
    if (iter == pools_.end()) {
        IAM_LOGE("ReleaseTaskThread %{public}s failed for no such name", name.c_str());
        return false;
    }

    if (transaction == 0) {
        IAM_LOGE("ReleaseTaskThread %{public}s failed for invalid transaction", name.c_str());
        return false;
    }
    auto &group = iter->second;
    return group.ReleaseTaskThread(transaction);
}

bool ThreadGroups::PostTask(const std::string &name, uint64_t transaction, const Task &task)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = pools_.find(name);
    if (iter == pools_.end()) {
        IAM_LOGE("PostTask %{public}s failed for no such name", name.c_str());
        return false;
    }
    auto &group = iter->second;
    return group.PostTask(transaction, task);
}

ThreadGroups::ThreadGroup::ThreadGroup(std::deque<ThreadPoolPtr> &frees, const std::string &name, uint32_t threadNum)
    : frees_(frees),
      name_(name),
      threadNum_(threadNum)
{
    IAM_LOGI("thread group %{public}s construct, thread num is %{public}u,", name_.c_str(), threadNum_);
}

ThreadGroups::ThreadGroup::~ThreadGroup()
{
    IAM_LOGI("group %{public}s destruct, thread num is %{public}u,", name_.c_str(), threadNum_);
}

bool ThreadGroups::ThreadGroup::RetainTaskThread(uint64_t transaction, uint32_t maxTaskNum)
{
    auto index = static_cast<uint32_t>(transaction);
    std::lock_guard<std::mutex> lock(mutex_);
    if (retains_.size() >= threadNum_) {
        IAM_LOGE("thread in group %{public}s retain failed, reason is overload, transaction is ****%{public}u.",
            name_.c_str(), index);
        return false;
    }

    auto iter = retains_.find(transaction);
    if (iter != retains_.end()) {
        IAM_LOGE("thread in group %{public}s retain failed, reason is duplicate, transaction is ****%{public}u.",
            name_.c_str(), index);
        return false;
    }

    if (frees_.empty()) {
        auto ptr = std::make_unique<ThreadPool>();
        ptr->Start(THREAD_NUM_SINGLE);
        frees_.push_back(std::move(ptr));
    }

    retains_[transaction] = std::move(frees_.front());
    frees_.pop_front();
    retains_[transaction]->SetMaxTaskNum(static_cast<int>(maxTaskNum));
    EnsureTransaction(retains_[transaction], transaction, name_);
    IAM_LOGI("thread in group %{public}s retain success, transaction is ****%{public}u.", name_.c_str(), index);
    return true;
}

bool ThreadGroups::ThreadGroup::ReleaseTaskThread(uint64_t transaction)
{
    auto index = static_cast<uint32_t>(transaction);
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = retains_.find(transaction);
    if (iter == retains_.end()) {
        IAM_LOGE("thread in group %{public}s release failed, reason is invalid transaction ****%{public}u.",
            name_.c_str(), index);
        return false;
    }

    auto &ptr = iter->second;
    EnsureTransaction(ptr, 0, name_);
    frees_.push_back(std::move(ptr));
    retains_.erase(iter);
    while (frees_.size() > THREAD_NUM_KEEP) {
        frees_.pop_front();
    }

    IAM_LOGI("thread in group %{public}s release success, transaction is ****%{public}u,", name_.c_str(), index);
    return true;
}

bool ThreadGroups::ThreadGroup::ReleaseAllTaskThread()
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto &iter : retains_) {
        auto ptr = std::move(iter.second);
        if (ptr != nullptr) {
            EnsureTransaction(ptr, 0, name_);
            frees_.push_back(std::move(ptr));
        }
    }
    while (frees_.size() > THREAD_NUM_KEEP) {
        frees_.pop_front();
    }
    retains_.clear();

    IAM_LOGI("thread in group %{public}s clear success", name_.c_str());
    return true;
}

bool ThreadGroups::ThreadGroup::PostTask(uint64_t transaction, const Task &task)
{
    auto index = static_cast<uint32_t>(transaction);

    std::lock_guard<std::mutex> lock(mutex_);

    auto iter = retains_.find(transaction);
    if (iter == retains_.end()) {
        IAM_LOGE("thread in group %{public}s submit failed, reason is invalid transaction ****%{public}u.",
            name_.c_str(), index);
        return false;
    }
    auto &ptr = iter->second;
    if (ptr == nullptr) {
        retains_.erase(iter);
        IAM_LOGE("thread in group %{public}s submit failed, reason is invalid transaction ****%{public}u.",
            name_.c_str(), index);
        return false;
    }
    ptr->AddTask(task);
    IAM_LOGI("thread in group %{public}s submit success, transaction is ****%{public}u,", name_.c_str(), index);
    return true;
}

void ThreadGroups::ThreadGroup::EnsureTransaction(const ThreadPoolPtr &poolPtr, uint64_t transaction,
    const std::string &name)
{
    auto task = [transaction, name]() {
        std::stringstream sstream;
        std::string taskName;
        if (transaction == 0) {
            sstream << "thread-idle";
        } else {
            sstream << name << ":" << std::hex << transaction;
        }
        sstream >> taskName;
        prctl(PR_SET_NAME, taskName.c_str(), 0, 0, 0);
        ThreadGroup::transactionCurr_ = transaction;
    };
    poolPtr->AddTask(task);
}

thread_local uint64_t ThreadGroups::ThreadGroup::transactionCurr_ = 0;
} // namespace Utils
} // namespace UserIAM
} // namespace OHOS