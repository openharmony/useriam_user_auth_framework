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

#ifndef USER_ACCESS_CTRL_CALLBACK_SERVICE_H
#define USER_ACCESS_CTRL_CALLBACK_SERVICE_H

#include "verify_token_callback_stub.h"

#include "iam_hitrace_helper.h"
#include "user_access_ctrl_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class VerifyTokenCallbackService : public VerifyTokenCallbackStub {
public:
    explicit VerifyTokenCallbackService(const std::shared_ptr<VerifyTokenCallback> &impl);
    ~VerifyTokenCallbackService() override;
    int32_t OnVerifyTokenResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<VerifyTokenCallback> verifyTokenCallback_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_CALLBACK_SERVICE_H
