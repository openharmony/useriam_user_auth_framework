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

#ifndef CRED_INFO_IMPL_H
#define CRED_INFO_IMPL_H

#include "user_idm_callback_interface.h"

#include "nocopyable.h"
#include "user_idm_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CredInfoImpl final : public IdmGetCredInfoCallbackInterface::CredentialInfo, public NoCopyable {
public:
    CredInfoImpl(uint64_t credentialId, uint64_t templateId, AuthType authType);
    ~CredInfoImpl() override = default;
    uint64_t GetCredentialId() const override;
    int32_t GetUserId() const override;
    uint64_t GetExecutorIndex() const override;
    uint64_t GetTemplateId() const override;
    AuthType GetAuthType() const override;
    uint32_t GetExecutorSensorHint() const override;
    uint32_t GetExecutorMatcher() const override;

private:
    uint64_t credentialId_ {0};
    uint64_t templateId_ {0};
    AuthType authType_ {};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CRED_INFO_IMPL_H