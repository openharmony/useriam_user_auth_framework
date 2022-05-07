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

#ifndef IAM_UTILS_THREAD_GROUPS_H
#define IAM_UTILS_THREAD_GROUPS_H

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "nocopyable.h"
#include "singleton.h"
#include "thread_pool.h"

namespace OHOS {
namespace UserIAM {
namespace Common {
using namespace OHOS;

constexpr uint32_t GROUP_MAX_THREAD_NUM = 4;
constexpr uint32_t THREAD_MAX_TASK_NUM = 128;

class ThreadGroups final : public Singleton<ThreadGroups> {
    using Task = ThreadPool::Task;
    using ThreadPoolPtr = std::unique_ptr<ThreadPool>;

public:
    bool CreateThreadGroup(const std::string &name, uint32_t threadNum = GROUP_MAX_THREAD_NUM);
    bool DestroyThreadGroup(const std::string &name);

    bool RetainTaskThread(const std::string &name, uint64_t transaction, uint32_t maxTaskNum = THREAD_MAX_TASK_NUM);
    bool ReleaseTaskThread(const std::string &name, uint64_t transaction);

    bool PostTask(const std::string &name, uint64_t transaction, const Task &task);
    template <typename T, typename... Args, typename = std::enable_if_t<std::is_function_v<T> && !std::is_class_v<T>>>
    bool PostTask(const std::string &name, uint64_t transaction, const T &task, Args &&...args)
    {
        static_assert(std::is_invocable<typename std::decay<T>::type, typename std::decay<Args>::type...>::value,
            "arguments cannot invocable");
        auto invoker = [task, tuple = std::make_tuple(std::forward<Args>(args)...)]() mutable {
            std::apply([task](auto &&...args) { std::invoke(task, std::forward<Args>(args)...); }, tuple);
        };
        return PostTask(name, transaction, invoker);
    }
    static uint64_t GetCurrTransaction()
    {
        return ThreadGroup::transactionCurr_;
    }

private:
    class ThreadGroup;
    std::mutex mutex_;
    std::map<std::string, ThreadGroup> pools_;
    std::deque<ThreadPoolPtr> frees_;

    class ThreadGroup final {
        DISALLOW_COPY_AND_MOVE(ThreadGroup);
        friend ThreadGroups;

    public:
        ThreadGroup(std::deque<ThreadPoolPtr> &frees, const std::string &name, uint32_t threadNum);
        ~ThreadGroup();
        bool RetainTaskThread(uint64_t transaction, uint32_t maxTaskNum = THREAD_MAX_TASK_NUM);
        bool ReleaseTaskThread(uint64_t transaction);
        bool ReleaseAllTaskThread();
        bool PostTask(uint64_t transaction, const Task &task);

    private:
        static void EnsureTransaction(const ThreadPoolPtr &poolPtr, uint64_t transaction, const std::string &name);
        static thread_local uint64_t transactionCurr_;
        std::deque<ThreadPoolPtr> &frees_;
        std::string name_;
        uint32_t threadNum_;
        std::mutex mutex_;
        std::map<uint64_t, ThreadPoolPtr> retains_;
    };
};
} // namespace Common
} // namespace UserIAM
} // namespace OHOS

#endif // IAM_UTILS_THREAD_GROUPS_H