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

#ifndef IAM_CREDENTIAL_INFO_IMPL_H
#define IAM_CREDENTIAL_INFO_IMPL_H

#include "nocopyable.h"

#include "credential_info_interface.h"
#include "hdi_wrapper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CredentialInfoImpl final : public CredentialInfoInterface, public NoCopyable {
public:
    CredentialInfoImpl(int32_t userId, const HdiCredentialInfo &info);
    ~CredentialInfoImpl() override = default;
    uint64_t GetCredentialId() const override;
    int32_t GetUserId() const override;
    uint64_t GetExecutorIndex() const override;
    uint64_t GetTemplateId() const override;
    AuthType GetAuthType() const override;
    uint32_t GetExecutorSensorHint() const override;
    uint32_t GetExecutorMatcher() const override;
    PinSubType GetAuthSubType() const override;
    bool GetAbandonFlag() const override;
    int64_t GetValidPeriod() const override;

private:
    int32_t userId_;
    HdiCredentialInfo info_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CREDENTIAL_INFO_IMPL_H