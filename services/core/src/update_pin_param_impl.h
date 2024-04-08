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

#ifndef IAM_UPDATE_PIN_PARAM_IMPL_H
#define IAM_UPDATE_PIN_PARAM_IMPL_H

#include "nocopyable.h"

#include "update_pin_param_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UpdatePinParamImpl final : public UpdatePinParamInterface, public NoCopyable {
public:
    UpdatePinParamImpl(uint64_t oldCredentialId, std::vector<uint8_t> oldRootSecret, std::vector<uint8_t> rootSecret,
        std::vector<uint8_t> authToken);
    uint64_t GetOldCredentialId() const override;
    std::vector<uint8_t> GetOldRootSecret() const override;
    std::vector<uint8_t> GetRootSecret() const override;
    std::vector<uint8_t> GetAuthToken() const override;
private:
    uint64_t oldCredentialId_;
    std::vector<uint8_t> oldRootSecret_;
    std::vector<uint8_t> rootSecret_;
    std::vector<uint8_t> authToken_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_UPDATE_PIN_PARAM_IMPL_H