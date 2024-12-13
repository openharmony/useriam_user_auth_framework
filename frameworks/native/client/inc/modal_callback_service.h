/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef MODAL_CALLBACK_SERVICE_H
#define MODAL_CALLBACK_SERVICE_H

#include "modal_callback_stub.h"

#include "iam_hitrace_helper.h"
#include "user_auth_modal_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ModalCallbackService : public ModalCallbackStub {
public:
    explicit ModalCallbackService(const std::shared_ptr<UserAuthModalClientCallback> &impl);
    ~ModalCallbackService() override;
    void SendCommand(uint64_t contextId, const std::string &cmdData) override;

private:
    std::shared_ptr<UserAuthModalClientCallback> modalCallback_ {nullptr};
    std::shared_ptr<UserIam::UserAuth::IamHitraceHelper> iamHitraceHelper_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MODAL_CALLBACK_SERVICE_H