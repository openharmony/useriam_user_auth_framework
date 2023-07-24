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

#ifndef WIDGET_CONTEXT_CALLBACK_IMPL_H
#define WIDGET_CONTEXT_CALLBACK_IMPL_H

#include <memory>
#include <mutex>

#include "iam_hitrace_helper.h"
#include "iam_defines.h"
#include "iam_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class WidgetContext;
class WidgetContextCallbackImpl : public IamCallbackInterface, public NoCopyable {
public:
    WidgetContextCallbackImpl(std::weak_ptr<WidgetContext> widgetContext, int32_t authType);
    ~WidgetContextCallbackImpl() override = default;
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo) override;
    sptr<IRemoteObject> AsObject() override;

private:
    std::mutex mutex_;
    int32_t authType_ {0};
    std::weak_ptr<WidgetContext> widgetContext_;
    std::shared_ptr<IamHitraceHelper> iamHitraceHelper_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // WIDGET_CONTEXT_CALLBACK_IMPL_H
