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

#ifndef EXECUTOR_MANAGER_H
#define EXECUTOR_MANAGER_H

#include <singleton.h>
#include "co_auth_defines.h"
#include "executor_callback.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class ExecutorMgr : public DelayedRefSingleton<ExecutorMgr> {
public:
    void Register(const ExecutorInfo &info, std::shared_ptr<ExecutorCallback> callback);
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS
#endif // EXECUTOR_MANAGER_H