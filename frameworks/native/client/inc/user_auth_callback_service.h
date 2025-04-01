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

#ifndef USER_AUTH_CALLBACK_SERVICE_H
#define USER_AUTH_CALLBACK_SERVICE_H

#include "iam_callback_stub.h"

#include "iam_hitrace_helper.h"
#include "get_executor_property_callback_stub.h"
#include "set_executor_property_callback_stub.h"
#include "user_auth_client_callback.h"
#include "user_auth_modal_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthCallbackService : public IamCallbackStub {
public:
    explicit UserAuthCallbackService(const std::shared_ptr<AuthenticationCallback> &impl);
    explicit UserAuthCallbackService(const std::shared_ptr<AuthenticationCallback> &impl,
        const std::shared_ptr<UserAuthModalClientCallback> &modalCallback);
    explicit UserAuthCallbackService(const std::shared_ptr<IdentificationCallback> &impl);
    explicit UserAuthCallbackService(const std::shared_ptr<PrepareRemoteAuthCallback> &impl);
    ~UserAuthCallbackService() override;
    int32_t OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo) override;
    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<AuthenticationCallback> authCallback_ {nullptr};
    std::shared_ptr<UserAuthModalClientCallback> modalCallback_ {nullptr};
    std::shared_ptr<IdentificationCallback> identifyCallback_ {nullptr};
    std::shared_ptr<PrepareRemoteAuthCallback> prepareRemoteAuthCallback_ {nullptr};
    std::shared_ptr<UserIam::UserAuth::IamHitraceHelper> iamHitraceHelper_ {nullptr};
};

class GetExecutorPropertyCallbackService : public GetExecutorPropertyCallbackStub {
public:
    explicit GetExecutorPropertyCallbackService(const std::shared_ptr<GetPropCallback> &impl);
    ~GetExecutorPropertyCallbackService() override;
    int32_t OnGetExecutorPropertyResult(int32_t resultCode, const std::vector<uint8_t> &attributes) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<GetPropCallback> getPropCallback_ {nullptr};
};

class SetExecutorPropertyCallbackService : public SetExecutorPropertyCallbackStub {
public:
    explicit SetExecutorPropertyCallbackService(const std::shared_ptr<SetPropCallback> &impl);
    ~SetExecutorPropertyCallbackService() override;
    int32_t OnSetExecutorPropertyResult(int32_t resultCode) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<SetPropCallback> setPropCallback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CALLBACK_SERVICE_H