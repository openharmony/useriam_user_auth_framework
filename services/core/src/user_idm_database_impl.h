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

#ifndef IAM_USER_IDM_DATABASE_IMPL_H
#define IAM_USER_IDM_DATABASE_IMPL_H

#include "user_idm_database.h"

#include <cinttypes>

#include "singleton.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmDatabaseImpl : public UserIdmDatabase, public Singleton<UserIdmDatabaseImpl> {
public:
    UserIdmDatabaseImpl() = default;
    ~UserIdmDatabaseImpl() override = default;
    std::shared_ptr<SecureUserInfoInterface> GetSecUserInfo(int32_t userId) override;
    std::vector<std::shared_ptr<CredentialInfoInterface>> GetCredentialInfo(int32_t userId,
        AuthType authType) override;
    int32_t DeleteCredentialInfo(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        std::shared_ptr<CredentialInfoInterface> &credInfo) override;
    int32_t DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos) override;
    int32_t DeleteUserEnforce(int32_t userId,
        std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos) override;
    std::vector<std::shared_ptr<UserInfoInterface>> GetAllExtUserInfo() override;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_USER_IDM_DATABASE_H