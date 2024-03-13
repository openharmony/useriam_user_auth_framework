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

#ifndef IAM_WIDGET_SCHEDULE_NODE_H
#define IAM_WIDGET_SCHEDULE_NODE_H

#include <cstdint>
#include <memory>
#include <optional>

#include "finite_state_machine.h"
#include "iam_common_defines.h"
#include "resource_node.h"
#include "widget_schedule_node_callback.h"
#include "thread_handler.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Context;
class WidgetScheduleNode {
public:
    enum State : uint32_t {
        S_WIDGET_INIT = 0,
        S_WIDGET_WAITING = 1,
        S_WIDGET_AUTH_RUNNING = 2,
        S_WIDGET_AUTH_FINISHED = 3
    };

    enum Event : uint32_t {
        E_START_WIDGET = 0,
        E_START_AUTH = 1,
        E_UPDATE_AUTH = 2,
        E_CANCEL_AUTH = 3,
        E_COMPLETE_AUTH = 4,
        E_NAVI_PIN_AUTH = 5,
        E_WIDGET_PARA_INVALID = 6
    };

    virtual ~WidgetScheduleNode() = default;
    virtual bool StartSchedule() = 0;
    virtual bool StopSchedule() = 0;
    virtual bool StartAuthList(const std::vector<AuthType> &authTypeList, bool endAfterFirstFail) = 0;
    virtual bool StopAuthList(const std::vector<AuthType> &authTypeList) = 0;
    virtual bool SuccessAuth(AuthType authType) = 0;
    virtual bool NaviPinAuth() = 0;
    virtual bool WidgetParaInvalid() = 0;
    virtual void SetCallback(std::shared_ptr<WidgetScheduleNodeCallback> callback) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_WIDGET_SCHEDULE_NODE_H