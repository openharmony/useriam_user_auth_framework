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

#ifndef USER_AUTH_INSTANCE_V9_H
#define USER_AUTH_INSTANCE_V9_H

#include <mutex>

#include "nocopyable.h"

#include "auth_common.h"

#include "user_auth_callback_v9.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthInstanceV9 : public NoCopyable {
public:
    static UserAuthResultCode GetAvailableStatus(napi_env env, napi_callback_info info);

    explicit AuthInstanceV9(napi_env env);
    ~AuthInstanceV9() override = default;

    UserAuthResultCode Init(napi_env env, napi_callback_info info);
    UserAuthResultCode On(napi_env env, napi_callback_info info);
    UserAuthResultCode Off(napi_env env, napi_callback_info info);
    UserAuthResultCode Start(napi_env env, napi_callback_info info);
    UserAuthResultCode Cancel(napi_env env, napi_callback_info info);

private:
    static bool CheckAuthType(int32_t authType);
    static bool CheckAuthTrustLevel(uint32_t authTrustLevel);

    napi_status InitChallenge(napi_env env, napi_value value);
    std::shared_ptr<JsRefHolder> GetCallback(napi_env env, napi_value value);

    std::vector<uint8_t> challenge_ = {};
    AuthType authType_ = FACE;
    AuthTrustLevel authTrustLevel_ = ATL1;
    uint64_t contextId_ = 0;
    bool isAuthStarted_ = false;
    std::mutex mutex_;
    std::shared_ptr<UserAuthCallbackV9> callback_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_INSTANCE_V9_H
