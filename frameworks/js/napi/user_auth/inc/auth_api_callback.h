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

#ifndef AUTHAPI_CALLBACK_H
#define AUTHAPI_CALLBACK_H

#include <vector>

#include "auth_common.h"
#include "user_auth_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
typedef struct AcquireInfoInner {
    napi_env env;
    napi_ref onAcquireInfo;
    int32_t module;
    uint32_t acquireInfo;
    int32_t extraInfo;
} AcquireInfoInner;

class AuthApiCallback : public UserIam::UserAuth::AuthenticationCallback {
public:
    explicit AuthApiCallback(AuthInfo *authInfo);
    explicit AuthApiCallback(ExecuteInfo *executeInfo);
    virtual ~AuthApiCallback();
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const UserIam::UserAuth::Attributes &extraInfo) override;
    void OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo) override;

    static napi_value BuildOnResult(
        napi_env env, uint32_t remainTimes, uint32_t freezingTime, std::vector<uint8_t> token);
    static napi_value Uint8ArrayToNapi(napi_env env, std::vector<uint8_t> value);

private:
    void OnAuthAcquireInfo(AcquireInfoInner *acquireInfoInner);
    void OnUserAuthResult(const int32_t result, const UserIam::UserAuth::Attributes &extraInfo);
    void OnAuthResult(const int32_t result, const UserIam::UserAuth::Attributes &extraInfo);
    void OnExecuteResult(const int32_t result);

    AuthInfo *authInfo_;
    ExecuteInfo *executeInfo_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // AUTHAPI_CALLBACK_H
