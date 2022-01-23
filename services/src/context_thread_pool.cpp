/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "context_thread_pool.h"
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
ContextThreadPool::ContextThreadPool(const std::string &name) : ThreadPool(name) {
}

ContextThreadPool::~ContextThreadPool() {
}

ContextThreadPool &ContextThreadPool::GetInstance()
{
    static ContextThreadPool instance(THREADPOOLNAME);
    return instance;
}

bool ContextThreadPool::AddTask(const uint64_t context, const ThreadPool::Task& f)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "userauth AddTask is start!");
    std::lock_guard<std::mutex> taskMutexGuard(taskMutex_);
    if (ThreadPool::GetCurTaskNum() >= ThreadPool::GetMaxTaskNum()) {
        return false;
    }
    ContextTask contextTask;
    bool hasContextTask = false;
    if (ctMap_.count(context) != 0) {
        hasContextTask = true;
        contextTask = ctMap_[context];
    }
    auto task = std::bind(&ContextThreadPool::TaskFunction, this, context, f);
    if (!hasContextTask) {
        ThreadPool::AddTask(task);
    } else {
        contextTask.AddTask(task);
    }
    ctMap_[context] = contextTask;
    return true;
}

void ContextThreadPool::TaskFunction(const uint64_t context, const ThreadPool::Task& f)
{
    f();
    ThreadPool::Task next = CheckTask(context);
    if (next != nullptr) {
        next();
    }
}

ThreadPool::Task ContextThreadPool::CheckTask(const uint64_t context)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "userauth CheckTask is start!");
    std::lock_guard<std::mutex> taskMutexGuard(taskMutex_);
    if (ctMap_.count(context) != 0) {
        ContextTask contextTask = ctMap_[context];
        ThreadPool::Task next = contextTask.GetTask();
        ctMap_[context] = contextTask;
        if (next == nullptr) {
            ctMap_.erase(context);
        }
        return next;
    }
    return nullptr;
}

ContextThreadPool::ContextTask::ContextTask() {
}

ContextThreadPool::ContextTask::~ContextTask() {
}

ThreadPool::Task ContextThreadPool::ContextTask::GetTask()
{
    if (!tasks.empty()) {
        Task f = tasks.front();
        tasks.erase(tasks.begin());
        return f;
    }
    return nullptr;
}

void ContextThreadPool::ContextTask::AddTask(const ThreadPool::Task& f)
{
    tasks.push_back(f);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
