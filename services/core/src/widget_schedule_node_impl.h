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

#ifndef IAM_WIDGET_SCHEDULE_NODE_IMPL_H
#define IAM_WIDGET_SCHEDULE_NODE_IMPL_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <set>

#include "iam_hitrace_helper.h"

#include "finite_state_machine.h"
#include "resource_node.h"
#include "widget_schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetScheduleNodeImpl final : public WidgetScheduleNode,
                               public std::enable_shared_from_this<WidgetScheduleNodeImpl>,
                               public NoCopyable {
public:
    class Inner;
    explicit WidgetScheduleNodeImpl();
    ~WidgetScheduleNodeImpl() override = default;
    bool StartSchedule() override;
    bool StopSchedule() override;
    bool StartAuthList(const std::vector<AuthType> &authTypeList) override;
    bool StopAuthList(const std::vector<AuthType> &authTypeList) override;
    bool SuccessAuth(AuthType authType) override;
    bool NaviPinAuth() override;
    void SetCallback(WidgetScheduleNodeCallback *callback) override;

protected:
    void OnStartSchedule(FiniteStateMachine &machine, uint32_t event);
    void OnStopSchedule(FiniteStateMachine &machine, uint32_t event);
    void OnStartAuth(FiniteStateMachine &machine, uint32_t event);
    void OnStopAuthList(FiniteStateMachine &machine, uint32_t event);
    void OnSuccessAuth(FiniteStateMachine &machine, uint32_t event);
    void OnNaviPinAuth(FiniteStateMachine &machine, uint32_t event);

private:
    std::shared_ptr<FiniteStateMachine> MakeFiniteStateMachine();
    std::string GetDescription() const;
    bool TryKickMachine(Event event);
    std::shared_ptr<ThreadHandler> threadHandler_ {nullptr};
    std::shared_ptr<FiniteStateMachine> machine_ {nullptr};
    std::mutex mutex_;
    std::shared_ptr<IamHitraceHelper> iamHitraceHelper_ {nullptr};
    WidgetScheduleNodeCallback *callback_ {nullptr};
    AuthType authType_;
    AuthType success_authType_;
    std::set<AuthType> startAuthTypeList_;
    std::vector<AuthType> stopAuthTypeList_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_SCHEDULE_NODE_IMPL_H