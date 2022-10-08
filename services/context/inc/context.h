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

#ifndef IAM_CONTEXT_H
#define IAM_CONTEXT_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum ContextState {
    STATE_INIT,
    STATE_RUNNING,
    STATE_END,
};

enum ContextType {
    CONTEXT_SIMPLE_AUTH,
    CONTEXT_ENROLL,
    CONTEXT_IDENTIFY,
    WIDGET_AUTH_CONTEXT,
};

class Context {
public:
    using ContextStopCallback = std::function<void()>;
    virtual ~Context() = default;
    virtual bool Start() = 0;
    virtual bool Stop() = 0;
    virtual uint64_t GetContextId() const = 0;
    virtual ContextType GetContextType() const = 0;
    virtual std::shared_ptr<ScheduleNode> GetScheduleNode(uint64_t scheduleId) const = 0;
    virtual int32_t GetLatestError() const = 0;

protected:
    virtual void SetLatestError(int32_t error) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_H