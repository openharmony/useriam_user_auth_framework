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

#ifndef IAM_SCHEDULE_NODE_IMPL_H
#define IAM_SCHEDULE_NODE_IMPL_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

#include "iam_hitrace_helper.h"

#include "finite_state_machine.h"
#include "resource_node.h"
#include "schedule_node.h"
#include "schedule_node_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ScheduleNodeImpl final : public ScheduleNode,
                               public std::enable_shared_from_this<ScheduleNodeImpl>,
                               public NoCopyable {
public:
    friend class ScheduleNodeBuilder;
    class Inner;
    struct ScheduleInfo {
        uint64_t scheduleId {0};
        std::optional<uint32_t> tokenId;
        PinSubType pinSubType {0};
        uint64_t contextId {0};
        uint64_t expiredTime {0};
        std::vector<uint64_t> templateIdList {};
        AuthType authType {PIN};
        uint32_t executorMatcher {0};
        ScheduleMode scheduleMode {AUTH};
        std::weak_ptr<ResourceNode> collector;
        std::weak_ptr<ResourceNode> verifier;
        std::shared_ptr<ThreadHandler> threadHandler;
        std::shared_ptr<ScheduleNodeCallback> callback;
        std::shared_ptr<Attributes> parameters;
    };
    explicit ScheduleNodeImpl(ScheduleInfo &info);
    ~ScheduleNodeImpl() override = default;
    uint64_t GetScheduleId() const override;
    uint64_t GetContextId() const override;
    AuthType GetAuthType() const override;
    uint64_t GetExecutorMatcher() const override;
    ScheduleMode GetScheduleMode() const override;
    std::weak_ptr<ResourceNode> GetCollectorExecutor() const override;
    std::weak_ptr<ResourceNode> GetVerifyExecutor() const override;
    std::optional<std::vector<uint64_t>> GetTemplateIdList() const override;
    State GetCurrentScheduleState() const override;
    bool StartSchedule() override;
    bool StopSchedule() override;
    bool ContinueSchedule(ExecutorRole srcRole, ExecutorRole dstRole, uint64_t transNum,
        const std::vector<uint8_t> &msg) override;
    bool ContinueSchedule(ResultCode resultCode, const std::shared_ptr<Attributes> &finalResult) override;

private:
    std::shared_ptr<FiniteStateMachine> MakeFiniteStateMachine();
    std::string GetDescription() const;
    bool TryKickMachine(Event event);
    void SetFwkResultCode(int32_t resultCode);
    void SetExecutorResultCode(int32_t resultCode);
    void SetScheduleResult(const std::shared_ptr<Attributes> &scheduleResult);
    void StartTimer();
    void StopTimer();
    // fsm processes begins
    void ProcessBeginVerifier(FiniteStateMachine &machine, uint32_t event);
    void ProcessBeginCollector(FiniteStateMachine &machine, uint32_t event);
    // fsm processes begins ack
    void ProcessVerifierBeginFailed(FiniteStateMachine &machine, uint32_t event);
    void ProcessCollectorBeginFailed(FiniteStateMachine &machine, uint32_t event);
    // fsm processes wait
    void ProcessScheduleResultReceived(FiniteStateMachine &machine, uint32_t event) const;
    // fsm processes ends
    void ProcessEndCollector(FiniteStateMachine &machine, uint32_t event);
    void ProcessEndVerifier(FiniteStateMachine &machine, uint32_t event);

    void OnScheduleProcessing(FiniteStateMachine &machine, uint32_t event) const;
    void OnScheduleFinished(FiniteStateMachine &machine, uint32_t event);
    uint32_t timerId_ {0};
    // members
    ScheduleInfo info_;
    std::shared_ptr<FiniteStateMachine> machine_;
    std::mutex mutex_;
    std::shared_ptr<IamHitraceHelper> iamHitraceHelper_;
    // result
    int32_t executorResultCode_ {GENERAL_ERROR};
    std::optional<int32_t> fwkResultCode_ {std::nullopt};
    std::shared_ptr<Attributes> scheduleResult_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SCHEDULE_NODE_IMPL_H