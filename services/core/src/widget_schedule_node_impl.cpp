/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "widget_schedule_node_impl.h"

#include <mutex>
#include <sstream>

#include "nocopyable.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_para2str.h"
#include "iam_common_defines.h"
#include "relative_timer.h"
#include "user_auth_common_defines.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetScheduleNodeImpl::WidgetScheduleNodeImpl()
{
    machine_ = MakeFiniteStateMachine();
    if (machine_ == nullptr) {
        IAM_LOGE("Failed to create make FSM of widget schedule");
        return;
    }
    threadHandler_ = ThreadHandler::GetSingleThreadInstance();
    machine_->SetThreadHandler(threadHandler_);
}

std::shared_ptr<FiniteStateMachine> WidgetScheduleNodeImpl::MakeFiniteStateMachine()
{
    auto builder = FiniteStateMachine::Builder::New("widget_schedule", S_WIDGET_INIT);
    if (builder == nullptr) {
        return nullptr;
    }
    builder->MakeTransition(S_WIDGET_INIT, E_START_WIDGET, S_WIDGET_WAITING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStartSchedule(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_START_AUTH, S_WIDGET_AUTH_RUNNING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStartAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_CANCEL_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStopSchedule(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_NAVI_PIN_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnNaviPinAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_COMPLETE_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnSuccessAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_CANCEL_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStopSchedule(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_NAVI_PIN_AUTH, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnNaviPinAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_START_AUTH, S_WIDGET_AUTH_RUNNING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStartAuth(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_UPDATE_AUTH, S_WIDGET_AUTH_RUNNING,
        [this](FiniteStateMachine &machine, uint32_t event) { OnStopAuthList(machine, event); });
    builder->MakeTransition(S_WIDGET_WAITING, E_WIDGET_PARA_INVALID, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetParaInvalid(machine, event); });
    builder->MakeTransition(S_WIDGET_AUTH_RUNNING, E_WIDGET_PARA_INVALID, S_WIDGET_AUTH_FINISHED,
        [this](FiniteStateMachine &machine, uint32_t event) { OnWidgetParaInvalid(machine, event); });

    return builder->Build();
}

bool WidgetScheduleNodeImpl::TryKickMachine(Event event)
{
    if (machine_ == nullptr) {
        IAM_LOGE("Invalid FSM of widget schedule");
        return false;
    }
    machine_->Schedule(event);
    return true;
}

bool WidgetScheduleNodeImpl::StartSchedule()
{
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>("widget_schedule");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!TryKickMachine(E_START_WIDGET)) {
            return false;
        }
    }
    return true;
}

bool WidgetScheduleNodeImpl::StopSchedule()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TryKickMachine(E_CANCEL_AUTH);
}

bool WidgetScheduleNodeImpl::StartAuthList(const std::vector<AuthType> &authTypeList, bool endAfterFirstFail)
{
    std::lock_guard<std::mutex> lock(mutex_);
    startAuthTypeList_.clear();
    for (auto authType : authTypeList) {
        startAuthTypeList_.emplace_back(authType);
        IAM_LOGI("Command(type:%{public}d) on result start.", authType);
    }
    endAfterFirstFail_ = endAfterFirstFail;
    return TryKickMachine(E_START_AUTH);
}

bool WidgetScheduleNodeImpl::StopAuthList(const std::vector<AuthType> &authTypeList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    stopAuthTypeList_ = authTypeList;
    return TryKickMachine(E_UPDATE_AUTH);
}

bool WidgetScheduleNodeImpl::SuccessAuth(AuthType authType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    successAuthType_ = authType;
    IAM_LOGI("success %{public}d.", E_COMPLETE_AUTH);
    return TryKickMachine(E_COMPLETE_AUTH);
}

bool WidgetScheduleNodeImpl::NaviPinAuth()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TryKickMachine(E_NAVI_PIN_AUTH);
}

bool WidgetScheduleNodeImpl::WidgetParaInvalid()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TryKickMachine(E_WIDGET_PARA_INVALID);
}

void WidgetScheduleNodeImpl::SetCallback(std::shared_ptr<WidgetScheduleNodeCallback> callback)
{
    callback_ = callback;
}

void WidgetScheduleNodeImpl::OnStartSchedule(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    if (!callback->LaunchWidget()) {
        IAM_LOGE("Failed to launch widget, cancel Auth");
        StopSchedule();
    }
}

void WidgetScheduleNodeImpl::OnStopSchedule(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    callback->EndAuthAsCancel();
    iamHitraceHelper_ = nullptr;
}

void WidgetScheduleNodeImpl::OnStartAuth(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    std::set<AuthType> startAuthTypeSet;
    for (auto authType : startAuthTypeList_) {
        if (runningAuthTypeSet_.find(authType) == runningAuthTypeSet_.end()) {
            startAuthTypeSet.emplace(authType);
        }
    }
    callback->ExecuteAuthList(startAuthTypeSet, endAfterFirstFail_);
}

void WidgetScheduleNodeImpl::OnStopAuthList(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    for (auto authType : stopAuthTypeList_) {
        runningAuthTypeSet_.erase(authType);
    }
    callback->StopAuthList(stopAuthTypeList_);
}

void WidgetScheduleNodeImpl::OnSuccessAuth(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    runningAuthTypeSet_.erase(successAuthType_);
    callback->SuccessAuth(successAuthType_);
}

void WidgetScheduleNodeImpl::OnNaviPinAuth(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    callback->EndAuthAsNaviPin();
}

void WidgetScheduleNodeImpl::OnWidgetParaInvalid(FiniteStateMachine &machine, uint32_t event)
{
    auto callback = callback_.lock();
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
    callback->EndAuthAsWidgetParaInvalid();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS