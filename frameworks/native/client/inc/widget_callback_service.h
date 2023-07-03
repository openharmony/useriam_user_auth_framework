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

#ifndef WIDGET_CALLBACK_SERVICE_H
#define WIDGET_CALLBACK_SERVICE_H

#include "widget_callback_stub.h"

#include "iam_hitrace_helper.h"
#include "iuser_auth_widget_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetCallbackService : public WidgetCallbackStub {
public:
    explicit WidgetCallbackService(const std::shared_ptr<IUserAuthWidgetCallback> &impl);
    ~WidgetCallbackService() override = default;
    void SendCommand(const std::string &cmdData) override;

private:
    std::shared_ptr<IUserAuthWidgetCallback> widgetCallback_ {nullptr};
    std::shared_ptr<UserIam::UserAuth::IamHitraceHelper> iamHitraceHelper_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // WIDGET_CALLBACK_SERVICE_H