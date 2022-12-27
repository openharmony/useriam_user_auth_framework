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
#include "schedule_node_impl.h"

#include <mutex>
#include <sstream>

#include "nocopyable.h"

#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_para2str.h"
#include "iam_common_defines.h"
#include "relative_timer.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ScheduleNodeImpl::ScheduleNodeImpl(ScheduleInfo &info) : info_(std::move(info))
{
    machine_ = MakeFiniteStateMachine();
    if (machine_ && info_.threadHandler == nullptr) {
        info_.threadHandler = ThreadHandler::GetSingleThreadInstance();
        machine_->SetThreadHandler(info_.threadHandler);
    }
    if (info_.parameters == nullptr) {
        info_.parameters = Common::MakeShared<Attributes>();
    }

    if (info_.parameters == nullptr) {
        return;
    }

    info_.parameters->SetInt32Value(Attributes::ATTR_SCHEDULE_MODE, info_.scheduleMode);

    if (info_.tokenId.has_value()) {
        info_.parameters->SetUint32Value(Attributes::ATTR_ACCESS_TOKEN_ID, info_.tokenId.value());
    }

    if (info_.pinSubType != 0) {
        info_.parameters->SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, info_.pinSubType);
    }

    if (info_.templateIdList.empty()) {
        return;
    }
    info_.parameters->SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, info_.templateIdList);
    if (info_.templateIdList.size() == 1) {
        info_.parameters->SetUint64Value(Attributes::ATTR_TEMPLATE_ID, *info_.templateIdList.begin());
    }
}

uint64_t ScheduleNodeImpl::GetScheduleId() const
{
    return info_.scheduleId;
}

uint64_t ScheduleNodeImpl::GetContextId() const
{
    return info_.contextId;
}

AuthType ScheduleNodeImpl::GetAuthType() const
{
    return info_.authType;
}

uint64_t ScheduleNodeImpl::GetExecutorMatcher() const
{
    return info_.executorMatcher;
}

ScheduleMode ScheduleNodeImpl::GetScheduleMode() const
{
    return info_.scheduleMode;
}

std::weak_ptr<ResourceNode> ScheduleNodeImpl::GetCollectorExecutor() const
{
    return info_.collector;
}

std::weak_ptr<ResourceNode> ScheduleNodeImpl::GetVerifyExecutor() const
{
    return info_.verifier;
}

std::optional<std::vector<uint64_t>> ScheduleNodeImpl::GetTemplateIdList() const
{
    if (info_.templateIdList.empty()) {
        return std::nullopt;
    }
    return info_.templateIdList;
}

ScheduleNode::State ScheduleNodeImpl::GetCurrentScheduleState() const
{
    if (machine_ == nullptr) {
        return S_INIT;
    }
    return static_cast<State>(machine_->GetCurrentState());
}

bool ScheduleNodeImpl::StartSchedule()
{
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>(GetDescription());
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!TryKickMachine(E_START_AUTH)) {
            return false;
        }
    }
    StartTimer();
    return true;
}

bool ScheduleNodeImpl::StopSchedule()
{
    std::lock_guard<std::mutex> lock(mutex_);

    SetFwkResultCode(CANCELED);
    return TryKickMachine(E_STOP_AUTH);
}

bool ScheduleNodeImpl::ContinueSchedule(ExecutorRole srcRole, ExecutorRole dstRole, uint64_t transNum,
    const std::vector<uint8_t> &msg)
{
    if (dstRole != SCHEDULER) {
        IAM_LOGE("not supported yet");
        return false;
    }

    if (info_.callback) {
        info_.callback->OnScheduleProcessed(srcRole, GetAuthType(), msg);
    }

    return true;
}

bool ScheduleNodeImpl::ContinueSchedule(ResultCode resultCode, const std::shared_ptr<Attributes> &finalResult)
{
    std::lock_guard<std::mutex> lock(mutex_);
    SetExecutorResultCode(resultCode);
    SetScheduleResult(finalResult);
    return TryKickMachine(E_SCHEDULE_RESULT_RECEIVED);
}

std::shared_ptr<FiniteStateMachine> ScheduleNodeImpl::MakeFiniteStateMachine()
{
    auto builder = FiniteStateMachine::Builder::New(GetDescription(), S_INIT);
    if (builder == nullptr) {
        return nullptr;
    }
    // S_INIT
    builder->MakeTransition(S_INIT, E_START_AUTH, S_VERIFY_STARING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessBeginVerifier(machine, event); });

    // S_VERIFY_STARING
    builder->MakeTransition(S_VERIFY_STARING, E_VERIFY_STARTED_SUCCESS, S_COLLECT_STARING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessBeginCollector(machine, event); });
    builder->MakeTransition(S_VERIFY_STARING, E_VERIFY_STARTED_FAILED, S_END,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessVerifierBeginFailed(machine, event); });
    builder->MakeTransition(S_VERIFY_STARING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_VERIFY_STARING, E_STOP_AUTH, S_END);
    builder->MakeTransition(S_VERIFY_STARING, E_TIME_OUT, S_END);

    // S_COLLECT_STARING
    builder->MakeTransition(S_COLLECT_STARING, E_COLLECT_STARTED_SUCCESS, S_AUTH_PROCESSING);
    builder->MakeTransition(S_COLLECT_STARING, E_SCHEDULE_RESULT_RECEIVED, S_END);

    // S_AUTH_PROCESSING
    builder->MakeTransition(S_AUTH_PROCESSING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_AUTH_PROCESSING, E_STOP_AUTH, S_COLLECT_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndCollector(machine, event); });
    builder->MakeTransition(S_AUTH_PROCESSING, E_TIME_OUT, S_COLLECT_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndCollector(machine, event); });

    // S_COLLECT_STOPPING
    builder->MakeTransition(S_COLLECT_STOPPING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_COLLECT_STOPPING, E_COLLECT_STOPPED_SUCCESS, S_VERIFY_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndVerifier(machine, event); });
    builder->MakeTransition(S_COLLECT_STOPPING, E_COLLECT_STOPPED_FAILED, S_VERIFY_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndVerifier(machine, event); });
    builder->MakeTransition(S_COLLECT_STOPPING, E_TIME_OUT, S_VERIFY_STOPPING,
        [this](FiniteStateMachine &machine, uint32_t event) { ProcessEndVerifier(machine, event); });

    // S_VERIFY_STOPPING
    builder->MakeTransition(S_VERIFY_STOPPING, E_SCHEDULE_RESULT_RECEIVED, S_END);
    builder->MakeTransition(S_VERIFY_STOPPING, E_VERIFY_STOPPED_SUCCESS, S_END);
    builder->MakeTransition(S_VERIFY_STOPPING, E_VERIFY_STOPPED_FAILED, S_END);
    builder->MakeTransition(S_VERIFY_STOPPING, E_TIME_OUT, S_END);

    // ENTERS
    builder->MakeOnStateEnter(S_AUTH_PROCESSING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnScheduleProcessing(machine, event); });
    builder->MakeOnStateEnter(S_END,
        [this](FiniteStateMachine &machine, uint32_t event) { OnScheduleFinished(machine, event); });
    return builder->Build();
}

std::string ScheduleNodeImpl::GetDescription() const
{
    std::stringstream stream;
    std::string name;

    auto verifier = info_.verifier.lock();
    stream << "schedule type:" << (verifier ? Common::AuthTypeToStr(verifier->GetAuthType()) : "nullptr") <<
        " id:******" << std::hex << static_cast<uint16_t>(GetScheduleId());
    stream >> name;
    return name;
}

bool ScheduleNodeImpl::TryKickMachine(Event event)
{
    if (machine_ == nullptr) {
        return false;
    }
    machine_->Schedule(event);
    return true;
}

void ScheduleNodeImpl::SetFwkResultCode(int32_t resultCode)
{
    fwkResultCode_ = resultCode;
}

void ScheduleNodeImpl::SetExecutorResultCode(int32_t resultCode)
{
    executorResultCode_ = resultCode;
}

void ScheduleNodeImpl::SetScheduleResult(const std::shared_ptr<Attributes> &scheduleResult)
{
    scheduleResult_ = scheduleResult;
}

void ScheduleNodeImpl::StartTimer()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (info_.expiredTime == 0 || timerId_ != 0) {
        return;
    }

    timerId_ = RelativeTimer::GetInstance().Register(
        [self = weak_from_this(), this] {
            if (self.lock()) {
                std::lock_guard<std::mutex> lock(mutex_);
                SetFwkResultCode(TIMEOUT);
                TryKickMachine(E_TIME_OUT);
            }
        },
        info_.expiredTime);
}

void ScheduleNodeImpl::StopTimer()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (timerId_ == 0) {
        return;
    }
    RelativeTimer::GetInstance().Unregister(timerId_);
    timerId_ = 0;
}

void ScheduleNodeImpl::ProcessBeginVerifier(FiniteStateMachine &machine, uint32_t event)
{
    auto collector = info_.collector.lock();
    auto verifier = info_.verifier.lock();
    if (collector == nullptr || verifier == nullptr) {
        SetFwkResultCode(GENERAL_ERROR);
        machine.Schedule(E_VERIFY_STARTED_FAILED);
        IAM_LOGE("invalid resource");
        return;
    }
    auto peerPk = collector->GetExecutorPublicKey();

    auto result = verifier->BeginExecute(info_.scheduleId, peerPk, *info_.parameters);
    if (result != SUCCESS) {
        IAM_LOGE("start verify failed, result = %{public}d", result);
        SetExecutorResultCode(result);
        machine.Schedule(E_VERIFY_STARTED_FAILED);
        return;
    }
    IAM_LOGI("start verify success");
    machine.Schedule(E_VERIFY_STARTED_SUCCESS);
}

void ScheduleNodeImpl::ProcessBeginCollector(FiniteStateMachine &machine, uint32_t event)
{
    auto collector = info_.collector.lock();
    auto verifier = info_.verifier.lock();
    if (collector == nullptr || verifier == nullptr) {
        SetFwkResultCode(GENERAL_ERROR);
        machine.Schedule(E_COLLECT_STARTED_FAILED);
        IAM_LOGE("invalid resource");
        return;
    }
    if (collector == verifier) {
        IAM_LOGE("all in one schedule, just wait the result");
        machine.Schedule(E_COLLECT_STARTED_SUCCESS);
        return;
    }
    IAM_LOGE("distributed auth not supported yet");
}

void ScheduleNodeImpl::ProcessVerifierBeginFailed(FiniteStateMachine &machine, uint32_t event)
{
    // just do nothing
}

void ScheduleNodeImpl::ProcessCollectorBeginFailed(FiniteStateMachine &machine, uint32_t event)
{
    // just do nothing
}

void ScheduleNodeImpl::ProcessScheduleResultReceived(FiniteStateMachine &machine, uint32_t event) const
{
    // just do nothing
}

void ScheduleNodeImpl::ProcessEndCollector(FiniteStateMachine &machine, uint32_t event)
{
    auto collector = info_.collector.lock();
    auto verifier = info_.verifier.lock();
    if (collector == nullptr || verifier == nullptr) {
        SetFwkResultCode(GENERAL_ERROR);
        machine.Schedule(E_COLLECT_STOPPED_FAILED);
        return;
    }
    if (collector == verifier) {
        IAM_LOGE("all in one schedule, just do noting");
        machine.Schedule(E_COLLECT_STOPPED_SUCCESS);
        return;
    }
    IAM_LOGE("distributed auth not supported yet");
}

void ScheduleNodeImpl::ProcessEndVerifier(FiniteStateMachine &machine, uint32_t event)
{
    auto verifier = info_.verifier.lock();
    if (verifier == nullptr) {
        SetFwkResultCode(GENERAL_ERROR);
        machine.Schedule(E_VERIFY_STOPPED_FAILED);
        return;
    }
    Attributes attr;
    auto result = verifier->EndExecute(info_.scheduleId, attr);
    if (result != SUCCESS) {
        IAM_LOGE("end verify failed, result = %{public}d", result);
        SetExecutorResultCode(result);
        machine.Schedule(E_VERIFY_STOPPED_FAILED);
        return;
    }
    machine.Schedule(E_VERIFY_STOPPED_SUCCESS);
}

void ScheduleNodeImpl::OnScheduleProcessing(FiniteStateMachine &machine, uint32_t event) const
{
    if (!info_.callback) {
        return;
    }
    info_.callback->OnScheduleStarted();
}

void ScheduleNodeImpl::OnScheduleFinished(FiniteStateMachine &machine, uint32_t event)
{
    StopTimer();
    if (!info_.callback) {
        return;
    }

    iamHitraceHelper_ = nullptr;

    int32_t result = fwkResultCode_.value_or(executorResultCode_);
    IAM_LOGI("schedule result = %{public}d", result);
    info_.callback->OnScheduleStoped(result, scheduleResult_);
    info_.callback = nullptr;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
