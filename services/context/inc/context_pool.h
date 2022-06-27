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

#ifndef IAM_CONTEXT_POOL_H
#define IAM_CONTEXT_POOL_H

#include <cstdint>

#include "context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextPool {
public:
    class ContextPoolListener {
    public:
        virtual void OnContextPoolInsert(const std::shared_ptr<Context> &context) = 0;
        virtual void OnContextPoolDelete(const std::shared_ptr<Context> &context) = 0;
    };
    static uint64_t GetNewContextId();
    static ContextPool &Instance();
    virtual bool Insert(const std::shared_ptr<Context> &context) = 0;
    virtual bool Delete(uint64_t contextId) = 0;
    virtual std::weak_ptr<Context> Select(uint64_t contextId) const = 0;
    virtual std::vector<std::weak_ptr<Context>> Select(ContextType contextType) const = 0;
    virtual std::shared_ptr<ScheduleNode> SelectScheduleNodeByScheduleId(uint64_t scheduleId) = 0;
    virtual bool RegisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener) = 0;
    virtual bool DeregisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_POOL_H
