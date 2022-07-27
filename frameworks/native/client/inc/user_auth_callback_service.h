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

#include "user_auth_callback_stub.h"

#include "iam_hitrace_helper.h"
#include "user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthCallbackService : public UserAuthCallbackStub {
public:
    explicit UserAuthCallbackService(const std::shared_ptr<AuthenticationCallback> &impl);
    explicit UserAuthCallbackService(const std::shared_ptr<IdentificationCallback> &impl);
    ~UserAuthCallbackService() override = default;
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, int32_t acquireInfo, const Attributes &extraInfo) override;

private:
    std::shared_ptr<AuthenticationCallback> authCallback_ {nullptr};
    std::shared_ptr<IdentificationCallback> identifyCallback_ {nullptr};
    std::shared_ptr<UserIam::UserAuth::IamHitraceHelper> iamHitraceHelper_ {nullptr};
};

class GetExecutorPropertyCallbackService : public GetExecutorPropertyCallbackStub {
public:
    explicit GetExecutorPropertyCallbackService(const std::shared_ptr<GetPropCallback> &impl);
    ~GetExecutorPropertyCallbackService() override = default;
    void OnGetExecutorPropertyResult(int32_t result, const Attributes &attributes) override;

private:
    std::shared_ptr<GetPropCallback> getPropCallback_ {nullptr};
};

class SetExecutorPropertyCallbackService : public SetExecutorPropertyCallbackStub {
public:
    explicit SetExecutorPropertyCallbackService(const std::shared_ptr<SetPropCallback> &impl);
    ~SetExecutorPropertyCallbackService() override = default;
    void OnSetExecutorPropertyResult(int32_t result) override;

private:
    std::shared_ptr<SetPropCallback> setPropCallback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CALLBACK_SERVICE_H