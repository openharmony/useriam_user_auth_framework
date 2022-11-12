/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_CALLBACK_V8_H
#define USER_AUTH_CALLBACK_V8_H

#include "nocopyable.h"

#include "auth_common.h"
#include "user_auth_napi_helper.h"
#include "user_auth_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthCallbackV8 : public std::enable_shared_from_this<UserAuthCallbackV8>,
                           public NoCopyable,
                           public AuthenticationCallback {
public:
    UserAuthCallbackV8(napi_env env,
        const std::shared_ptr<JsRefHolder> &resultCallback, const std::shared_ptr<JsRefHolder> &acquireCallback);
    ~UserAuthCallbackV8() override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

    napi_status DoResultCallback(int32_t result,
        const std::vector<uint8_t> &token, int32_t remainTimes, int32_t freezingTime);
    napi_status DoAcquireCallback(int32_t module, uint32_t acquireInfo);

private:
    napi_env env_ = nullptr;
    std::shared_ptr<JsRefHolder> resultCallback_ = nullptr;
    std::shared_ptr<JsRefHolder> acquireCallback_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CALLBACK_V8_H
