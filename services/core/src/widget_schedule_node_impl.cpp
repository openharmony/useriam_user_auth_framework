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

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetScheduleNodeImpl::WidgetScheduleNodeImpl()
{
    machine_ = MakeFiniteStateMachine();
    if (machine_) {
        threadHandler_ = ThreadHandler::GetSingleThreadInstance();
        machine_->SetThreadHandler(threadHandler_);
    }
}

std::shared_ptr<FiniteStateMachine> WidgetScheduleNodeImpl::MakeFiniteStateMachine()
{
    auto builder = FiniteStateMachine::Builder::New(GetDescription(), S_WIDGET_INIT);
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

    return builder->Build();
}

std::string WidgetScheduleNodeImpl::GetDescription() const
{
    std::ostringstream ss;
    ss << "schedule type: widget_schedule";
    return ss.str();
}

bool WidgetScheduleNodeImpl::TryKickMachine(Event event)
{
    if (machine_ == nullptr) {
        return false;
    }
    machine_->Schedule(event);
    return true;
}

bool WidgetScheduleNodeImpl::StartSchedule()
{
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>(GetDescription());
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

bool WidgetScheduleNodeImpl::StartAuthList(const std::vector<AuthType> &authTypeList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto authType : authTypeList) {
        startAuthTypeList_.insert(authType);
    }
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
    success_authType_ = authType;
    return TryKickMachine(E_COMPLETE_AUTH);
}

bool WidgetScheduleNodeImpl::NaviPinAuth()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TryKickMachine(E_NAVI_PIN_AUTH);
}

void WidgetScheduleNodeImpl::SetCallback(WidgetScheduleNodeCallback *callback)
{
    callback_ = callback;
}

void WidgetScheduleNodeImpl::OnStartSchedule(FiniteStateMachine &machine, uint32_t event)
{
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    callback_->LaunchWidget();
}

void WidgetScheduleNodeImpl::OnStopSchedule(FiniteStateMachine &machine, uint32_t event)
{
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    callback_->EndAuthAsCancel();
    iamHitraceHelper_ = nullptr;
}

void WidgetScheduleNodeImpl::OnStartAuth(FiniteStateMachine &machine, uint32_t event)
{
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    callback_->ExecuteAuthList(startAuthTypeList_);
}

void WidgetScheduleNodeImpl::OnStopAuthList(FiniteStateMachine &machine, uint32_t event)
{
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    callback_->StopAuthList(stopAuthTypeList_);
}

void WidgetScheduleNodeImpl::OnSuccessAuth(FiniteStateMachine &machine, uint32_t event)
{
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    callback_->SuccessAuth(success_authType_);
}

void WidgetScheduleNodeImpl::OnNaviPinAuth(FiniteStateMachine &machine, uint32_t event)
{
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    callback_->EndAuthAsNaviPin();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS