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

#include "cred_info_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
CredInfoImpl::CredInfoImpl(uint64_t credentialId, uint64_t templateId, AuthType authType)
    : credentialId_(credentialId), templateId_(templateId), authType_(authType)
{
}

uint64_t CredInfoImpl::GetCredentialId() const
{
    return credentialId_;
}

int32_t CredInfoImpl::GetUserId() const
{
    return 0;
}

uint64_t CredInfoImpl::GetExecutorIndex() const
{
    return 0;
}

uint64_t CredInfoImpl::GetTemplateId() const
{
    return templateId_;
}

AuthType CredInfoImpl::GetAuthType() const
{
    return authType_;
}

uint32_t CredInfoImpl::GetExecutorSensorHint() const
{
    return 0;
}

uint32_t CredInfoImpl::GetExecutorMatcher() const
{
    return 0;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS