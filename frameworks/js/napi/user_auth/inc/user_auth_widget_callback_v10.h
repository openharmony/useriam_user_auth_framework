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

#ifndef USER_AUTH_WIDGET_CALLBACK_V10_H
#define USER_AUTH_WIDGET_CALLBACK_V10_H

#include <mutex>

#include "nocopyable.h"

#include "auth_common.h"
#include "user_auth_napi_helper.h"
#include "iuser_auth_widget_callback.h"
#include "iam_common_defines.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthWidgetCallback : public IUserAuthWidgetCallback,
    public std::enable_shared_from_this<UserAuthWidgetCallback>, public NoCopyable {
public:
    explicit UserAuthWidgetCallback(napi_env env);
    ~UserAuthWidgetCallback() override;
    void SendCommand(const std::string &cmdData) override;
    void SetCommandCallback(const std::shared_ptr<JsRefHolder> &callback);
    void ClearCommandCallback();
    napi_status DoCommandCallback(const std::string &cmdData);
    bool HasCommandCallback();

private:
    std::shared_ptr<JsRefHolder> GetCommandCallback();

    napi_env env_ = nullptr;
    std::mutex mutex_;
    std::shared_ptr<JsRefHolder> commandCallback_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_WIDGET_CALLBACK_V10_H
