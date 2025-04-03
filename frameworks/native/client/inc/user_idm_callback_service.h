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

#include "iam_callback_stub.h"
#include "idm_get_cred_info_callback_stub.h"
#include "idm_get_secure_user_info_callback_stub.h"

#include "iam_hitrace_helper.h"
#include "user_idm_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IdmCallbackService : public IamCallbackStub {
public:
    explicit IdmCallbackService(const std::shared_ptr<UserIdmClientCallback> &impl);
    ~IdmCallbackService() override;
    int32_t OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo) override;
    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<UserIdmClientCallback> idmClientCallback_ {nullptr};
    std::shared_ptr<UserIam::UserAuth::IamHitraceHelper> iamHitraceHelper_ {nullptr};
};

class IdmGetCredInfoCallbackService : public IdmGetCredInfoCallbackStub {
public:
    explicit IdmGetCredInfoCallbackService(const std::shared_ptr<GetCredentialInfoCallback> &impl);
    ~IdmGetCredInfoCallbackService() override;
    int32_t OnCredentialInfos(int32_t resultCode, const std::vector<IpcCredentialInfo> &credInfoList) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<GetCredentialInfoCallback> getCredInfoCallback_ {nullptr};
};

class IdmGetSecureUserInfoCallbackService : public IdmGetSecureUserInfoCallbackStub {
public:
    explicit IdmGetSecureUserInfoCallbackService(const std::shared_ptr<GetSecUserInfoCallback> &impl);
    ~IdmGetSecureUserInfoCallbackService() override;
    int32_t OnSecureUserInfo(int32_t resultCode, const IpcSecUserInfo &ipcSecUserInfo) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<GetSecUserInfoCallback> getSecInfoCallback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_CALLBACK_SERVICE_H