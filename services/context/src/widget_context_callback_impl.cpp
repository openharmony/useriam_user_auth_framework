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

#include "widget_context_callback_impl.h"

#include <sstream>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_mem.h"
#include "iam_ptr.h"
#include "widget_context.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetContextCallbackImpl::WidgetContextCallbackImpl(WidgetContext *widgetContext, int32_t authType)
    : widgetContext_(widgetContext), authType_(authType)
{
    std::ostringstream ss;
    ss << "IDM(operation: Widget)";
    iamHitraceHelper_ = Common::MakeShared<IamHitraceHelper>(ss.str());
}

void WidgetContextCallbackImpl::OnResult(int32_t result, const Attributes &extraInfo)
{
    std::lock_guard lck(mutex_);
    if (widgetContext_ != nullptr) {
        auto task = widgetContext_->GetTaskFromIamcallback(shared_from_this());
        widgetContext_->AuthResult(result, authType_, extraInfo, task);
    }
}

void WidgetContextCallbackImpl::OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo)
{
}

sptr<IRemoteObject> WidgetContextCallbackImpl::AsObject()
{
    return nullptr;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
