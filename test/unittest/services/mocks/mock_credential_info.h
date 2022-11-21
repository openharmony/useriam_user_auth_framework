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
#ifndef IAM_MOCK_CREDENTIAL_INFO_H
#define IAM_MOCK_CREDENTIAL_INFO_H

#include <gmock/gmock.h>

#include "user_idm_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockCredentialInfo final : public IdmGetCredInfoCallbackInterface::CredentialInfo {
public:
    virtual ~MockCredentialInfo() = default;
    MOCK_CONST_METHOD0(GetCredentialId, uint64_t());
    MOCK_CONST_METHOD0(GetUserId, int32_t());
    MOCK_CONST_METHOD0(GetExecutorIndex, uint64_t());
    MOCK_CONST_METHOD0(GetTemplateId, uint64_t());
    MOCK_CONST_METHOD0(GetAuthType, AuthType());
    MOCK_CONST_METHOD0(GetExecutorSensorHint, uint32_t());
    MOCK_CONST_METHOD0(GetExecutorMatcher, uint32_t());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_CREDENTIAL_INFO_H