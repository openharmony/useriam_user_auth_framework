/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef IAM_CREDENTIAL_UPDATED_MANAGER
#define IAM_CREDENTIAL_UPDATED_MANAGER

#include "deletion.h"
#include "enrollment.h"
#include "user_idm_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CredentialUpdatedManager {
public:
    static CredentialUpdatedManager &GetInstance();
    void ProcessCredentialDeleted(const Deletion::DeleteParam &deletePara, uint64_t credentialId, AuthType authType);
    void ProcessCredentialEnrolled(const Enrollment::EnrollmentPara &enrollPara, const HdiEnrollResultInfo &resultInfo,
        bool isUpdate, uint64_t scheduleId);
    void ProcessUserDeleted(int32_t userId, CredChangeEventType eventType);

private:
    CredentialUpdatedManager() = default;
    ~CredentialUpdatedManager() = default;

    void SaveCredentialUpdatedEvent(int32_t userId, AuthType authType, CredChangeEventType eventType, uint32_t count);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CREDENTIAL_UPDATED_MANAGER