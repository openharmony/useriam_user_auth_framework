/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MOCK_IAM_THREAD_HANDLER_MANAGER_H
#define MOCK_IAM_THREAD_HANDLER_MANAGER_H

#include <map>
#include <mutex>
#include <string>

#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::string SINGLETON_THREAD_NAME = "ThreadHandler";
class ThreadHandlerManager {
public:
    static ThreadHandlerManager &GetInstance();
    ThreadHandlerManager();
    ~ThreadHandlerManager();

    bool CreateThreadHandler(const std::string &name);
    void DestroyThreadHandler(const std::string &name);
    void DeleteThreadHandler(const std::string &name);
    std::shared_ptr<ThreadHandler> GetThreadHandler(const std::string &name);
    void PostTask(const std::string &name, const std::function<void()> &task);
    void PostTaskOnTemporaryThread(const std::string &name, const std::function<void()> &task);
    void Stop();
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_IAM_THREAD_HANDLER_MANAGER_H