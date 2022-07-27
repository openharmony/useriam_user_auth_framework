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

#ifndef USER_IDM_CALLBACK_SERVICE_H
#define USER_IDM_CALLBACK_SERVICE_H

#include "user_idm_callback_stub.h"

#include "iam_hitrace_helper.h"
#include "user_idm_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdmCallbackService : public IdmCallbackStub {
public:
    explicit IdmCallbackService(const std::shared_ptr<UserIdmClientCallback> &impl);
    ~IdmCallbackService() override = default;
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo) override;

private:
    std::shared_ptr<UserIdmClientCallback> idmClientCallback_ {nullptr};
    std::shared_ptr<UserIam::UserAuth::IamHitraceHelper> iamHitraceHelper_ {nullptr};
};

class IdmGetCredInfoCallbackService : public IdmGetCredInfoCallbackStub {
public:
    explicit IdmGetCredInfoCallbackService(const std::shared_ptr<GetCredentialInfoCallback> &impl);
    ~IdmGetCredInfoCallbackService() override = default;
    void OnCredentialInfos(const std::vector<std::shared_ptr<CredentialInfo>> infoList,
        const std::optional<PinSubType> pinSubType) override;

private:
    std::shared_ptr<GetCredentialInfoCallback> getCredInfoCallback_ {nullptr};
};

class IdmGetSecureUserInfoCallbackService : public IdmGetSecureUserInfoCallbackStub {
public:
    explicit IdmGetSecureUserInfoCallbackService(const std::shared_ptr<GetSecUserInfoCallback> &impl);
    ~IdmGetSecureUserInfoCallbackService() override = default;
    void OnSecureUserInfo(const std::shared_ptr<SecureUserInfo> info) override;

private:
    std::shared_ptr<GetSecUserInfoCallback> getSecInfoCallback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_CALLBACK_SERVICE_H