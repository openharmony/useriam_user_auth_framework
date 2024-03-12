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

#include "user_auth_extension.h"

#include "js_user_auth_extension.h"
#include "runtime.h"

#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
UserAuthExtension* UserAuthExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    if (!runtime) {
        return new UserAuthExtension();
    }
    IAM_LOGD("Create runtime");
    switch (runtime->GetLanguage()) {
        case Runtime::Language::JS:
            return JsUserAuthExtension::Create(runtime);

        default:
            return new UserAuthExtension();
    }
}

void UserAuthExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    IAM_LOGD("begin init");
    ExtensionBase<UIExtensionContext>::Init(record, application, handler, token);
}

std::shared_ptr<UIExtensionContext> UserAuthExtension::CreateAndInitContext(
    const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    std::shared_ptr<UIExtensionContext> context =
        ExtensionBase<UIExtensionContext>::CreateAndInitContext(record, application, handler, token);
    if (context == nullptr) {
        IAM_LOGE("CreateAndInitContext context is nullptr");
        return context;
    }
    return context;
}
}
}
