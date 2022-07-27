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
#include "thread_handler.h"

#include <cstdint>
#include <functional>
#include <future>
#include <memory>

#include "nocopyable.h"
#include "singleton.h"
#include "thread_pool.h"

#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS;

class ThreadHandlerImpl : public ThreadHandler, public DelayedSingleton<ThreadHandlerImpl> {
public:
    ThreadHandlerImpl();
    ~ThreadHandlerImpl() override;
    void PostTask(const Task &task) override;
    void EnsureTask(const Task &task) override;

private:
    OHOS::ThreadPool pool_;
};

ThreadHandlerImpl::ThreadHandlerImpl()
{
    pool_.Start(1);
}

ThreadHandlerImpl::~ThreadHandlerImpl()
{
    pool_.Stop();
}

void ThreadHandlerImpl::PostTask(const Task &task)
{
    pool_.AddTask(task);
}

void ThreadHandlerImpl::EnsureTask(const Task &task)
{
    std::promise<void> ensure;
    auto callback = [&ensure]() {
        ensure.set_value();
        return;
    };
    pool_.AddTask(task);
    pool_.AddTask(callback);
    ensure.get_future().get();
}

std::shared_ptr<ThreadHandler> ThreadHandler::GetSingleThreadInstance()
{
    return ThreadHandlerImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS