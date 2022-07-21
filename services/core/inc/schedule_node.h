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

#ifndef IAM_SCHEDULE_NODE_H
#define IAM_SCHEDULE_NODE_H

#include <cstdint>
#include <memory>
#include <optional>

#include "iam_common_defines.h"
#include "finite_state_machine.h"
#include "resource_node.h"
#include "schedule_node_callback.h"
#include "thread_handler.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Context;
class ScheduleNode {
public:
    class Builder;
    enum State : uint32_t {
        S_INIT = 0,
        S_VERIFY_STARING = 1,
        S_COLLECT_STARING = 2,
        S_AUTH_PROCESSING = 3,
        S_COLLECT_STOPPING = 4,
        S_VERIFY_STOPPING = 5,
        S_END = 6
    };
    enum Event : uint32_t {
        E_START_AUTH = 0,
        E_VERIFY_STARTED_SUCCESS = 1,
        E_VERIFY_STARTED_FAILED = 2,
        E_COLLECT_STARTED_SUCCESS = 3,
        E_COLLECT_STARTED_FAILED = 4,
        E_SCHEDULE_RESULT_RECEIVED = 5,
        E_COLLECT_STOPPED_SUCCESS = 6,
        E_COLLECT_STOPPED_FAILED = 7,
        E_VERIFY_STOPPED_SUCCESS = 8,
        E_VERIFY_STOPPED_FAILED = 9,
        E_STOP_AUTH = 10,
        E_TIME_OUT = 11,
    };
    virtual ~ScheduleNode() = default;
    virtual uint64_t GetScheduleId() const = 0;
    virtual uint64_t GetContextId() const = 0;
    virtual AuthType GetAuthType() const = 0;
    virtual uint64_t GetExecutorMatcher() const = 0;
    virtual ScheduleMode GetScheduleMode() const = 0;
    virtual std::weak_ptr<ResourceNode> GetCollectorExecutor() const = 0;
    virtual std::weak_ptr<ResourceNode> GetVerifyExecutor() const = 0;
    virtual std::optional<std::vector<uint64_t>> GetTemplateIdList() const = 0;
    virtual State GetCurrentScheduleState() const = 0;
    virtual bool StartSchedule() = 0;
    virtual bool StopSchedule() = 0;
    virtual bool ContinueSchedule(ExecutorRole srcRole, ExecutorRole dstRole, uint64_t transNum,
        const std::vector<uint8_t> &msg) = 0;
    virtual bool ContinueSchedule(ResultCode resultCode, const std::shared_ptr<Attributes> &finalResult) = 0;
};

class ScheduleNode::Builder {
public:
    static std::shared_ptr<Builder> New(const std::shared_ptr<ResourceNode> &collector,
        const std::shared_ptr<ResourceNode> &verifier);
    virtual ~Builder() = default;
    virtual std::shared_ptr<Builder> SetScheduleId(uint64_t scheduleId) = 0;
    virtual std::shared_ptr<Builder> SetAccessTokenId(uint32_t tokenId) = 0;
    virtual std::shared_ptr<Builder> SetPinSubType(PinSubType pinSubType) = 0;
    virtual std::shared_ptr<Builder> SetTemplateIdList(const std::vector<uint64_t> &templateIdList) = 0;
    virtual std::shared_ptr<Builder> SetAuthType(AuthType authType) = 0;
    virtual std::shared_ptr<Builder> SetExecutorMatcher(uint32_t executorMatcher) = 0;
    virtual std::shared_ptr<Builder> SetScheduleMode(ScheduleMode scheduleMode) = 0;
    virtual std::shared_ptr<Builder> SetScheduleCallback(const std::shared_ptr<ScheduleNodeCallback> &callback) = 0;
    virtual std::shared_ptr<Builder> SetExpiredTime(uint32_t ms) = 0;
    virtual std::shared_ptr<Builder> SetParametersAttributes(const std::shared_ptr<Attributes> &parameters) = 0;
    virtual std::shared_ptr<Builder> SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler) = 0;
    virtual std::shared_ptr<ScheduleNode> Build() = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SCHEDULE_NODE_H