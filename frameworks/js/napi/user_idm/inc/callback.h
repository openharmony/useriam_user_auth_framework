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

#ifndef CALLBACK_H
#define CALLBACK_H

#include <mutex>
#include <vector>
#include <string>
#include <iostream>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "securec.h"

#include "user_idm_client.h"
#include "user_idm_client_callback.h"
#include "useridentity_manager.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class IIdmCallback : public UserIam::UserAuth::UserIdmClientCallback {
public:
    explicit IIdmCallback(AsyncCallbackContext *asyncCallbackContext);
    virtual ~IIdmCallback() = default;
    AsyncCallbackContext* asyncCallbackContext_;
    void OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const UserIam::UserAuth::Attributes &extraInfo) override;

private:
    std::mutex mutex_;
};

class GetInfoCallbackIDM : public UserIam::UserAuth::GetCredentialInfoCallback {
public:
    explicit GetInfoCallbackIDM(AsyncGetAuthInfo *asyncGetAuthInfo);
    virtual ~GetInfoCallbackIDM() = default;
    AsyncGetAuthInfo *asyncGetAuthInfo_;
    void OnCredentialInfo(const std::vector<UserIam::UserAuth::CredentialInfo> &infoList) override;
};

napi_value GetAuthInfoRet(napi_env env, AsyncGetAuthInfo *asyncGetAuthInfo);
} // namespace UserIDM
} // namespace UserIAM
} // namespace ohos
#endif // CALLBACK_H
