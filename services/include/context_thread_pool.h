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

#ifndef USERAUTH_THREADPOOL_H
#define USERAUTH_THREADPOOL_H
#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

#include "nocopyable.h"
#include "thread_pool.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
static constexpr char THREADPOOLNAME[] = "userauthThreadPool";
static constexpr uint64_t THREADPOOLMAXSTART = 3;
static constexpr uint64_t THREADPOOLMAXTASK = 6;

class ContextThreadPool : ThreadPool {
public:
    DISALLOW_COPY_AND_MOVE(ContextThreadPool);
    static ContextThreadPool &GetInstance();
    uint32_t Start(int threadsNum)
    {
        return ThreadPool::Start(threadsNum);
    }
    void Stop()
    {
        ThreadPool::Stop();
    }

    void SetMaxTaskNum(int maxSize)
    {
        ThreadPool::SetMaxTaskNum(maxSize);
    }

    // for testability
    size_t GetMaxTaskNum() const
    {
        return ThreadPool::GetMaxTaskNum();
    }
    size_t GetCurTaskNum()
    {
        return ThreadPool::GetCurTaskNum();
    }
    size_t GetThreadsNum() const
    {
        return ThreadPool::GetThreadsNum();
    }

    bool AddTask(const uint64_t context, const ThreadPool::Task &f);

    void TaskFunction(const uint64_t context, const ThreadPool::Task &f);

private:
    class ContextTask {
    public:
        explicit ContextTask();
        ~ContextTask();

        ThreadPool::Task GetTask();

        void AddTask(const ThreadPool::Task &f);

    private:
        std::vector<ThreadPool::Task> tasks;
    };
    explicit ContextThreadPool(const std::string &name);
    ~ContextThreadPool() override;
    ThreadPool::Task CheckTask(const uint64_t context);
    std::map<uint64_t, ContextTask> ctMap_;
    std::mutex taskMutex_;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif