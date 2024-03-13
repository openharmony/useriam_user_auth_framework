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

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
WidgetContextCallbackImpl::WidgetContextCallbackImpl(std::weak_ptr<WidgetContext> widgetContext, int32_t authType)
    : authType_(authType), widgetContext_(widgetContext),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("WidgetContext"))
{
}

void WidgetContextCallbackImpl::OnResult(int32_t result, const Attributes &extraInfo)
{
    std::lock_guard lock(mutex_);
    auto widgetContext = widgetContext_.lock();
    if (widgetContext != nullptr) {
        widgetContext->AuthResult(result, authType_, extraInfo);
    }
}

void WidgetContextCallbackImpl::OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo)
{
    std::lock_guard lock(mutex_);
    auto widgetContext = widgetContext_.lock();
    if (widgetContext != nullptr) {
        widgetContext->AuthTipInfo(acquireInfo, authType_, extraInfo);
    }
}

sptr<IRemoteObject> WidgetContextCallbackImpl::AsObject()
{
    sptr<IRemoteObject> tmp(nullptr);
    return tmp;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
