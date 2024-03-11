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

#ifndef IAM_MOCK_WIDGET_SCHEDULE_NODE_CALLBACK_H
#define IAM_MOCK_WIDGET_SCHEDULE_NODE_CALLBACK_H

#include <memory>

#include <gmock/gmock.h>

#include "widget_schedule_node_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockWidgetScheduleNodeCallback final : public WidgetScheduleNodeCallback {
public:
    MOCK_METHOD0(LaunchWidget, bool());
    MOCK_METHOD2(ExecuteAuthList, void(const std::set<AuthType> &authTypeList, bool endAfterFirstFail));
    MOCK_METHOD0(EndAuthAsCancel, void());
    MOCK_METHOD0(EndAuthAsNaviPin, void());
    MOCK_METHOD0(EndAuthAsWidgetParaInvalid, void());
    MOCK_METHOD1(StopAuthList, void(const std::vector<AuthType> &authTypeList));
    MOCK_METHOD1(SuccessAuth, void(AuthType authType));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_WIDGET_SCHEDULE_NODE_CALLBACK_H