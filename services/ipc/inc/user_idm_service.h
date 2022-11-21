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

#ifndef USER_IDM_SERVICE_H
#define USER_IDM_SERVICE_H

#include "user_idm_stub.h"

#include <memory>
#include <string>
#include <vector>

#include "system_ability.h"
#include "system_ability_definition.h"

#include "context.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmService : public SystemAbility, public UserIdmStub, public NoCopyable {
public:
    DECLARE_SYSTEM_ABILITY(UserIdmService);
    explicit UserIdmService(int32_t systemAbilityId, bool runOnCreate = false);
    ~UserIdmService() override = default;
    void OnStart() override;
    void OnStop() override;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge) override;
    void CloseSession(int32_t userId) override;
    int32_t GetCredentialInfo(int32_t userId, AuthType authType,
        const sptr<IdmGetCredInfoCallbackInterface> &callback) override;
    int32_t GetSecInfo(int32_t userId, const sptr<IdmGetSecureUserInfoCallbackInterface> &callback) override;
    void AddCredential(int32_t userId, const CredentialPara &credPara,
        const sptr<IdmCallbackInterface> &callback, bool isUpdate) override;
    void UpdateCredential(int32_t userId, const CredentialPara &credPara,
        const sptr<IdmCallbackInterface> &callback) override;
    int32_t Cancel(int32_t userId) override;
    int32_t EnforceDelUser(int32_t userId, const sptr<IdmCallbackInterface> &callback) override;
    void DelUser(int32_t userId, const std::vector<uint8_t> authToken,
        const sptr<IdmCallbackInterface> &callback) override;
    void DelCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const sptr<IdmCallbackInterface> &callback) override;

private:
    int32_t CancelCurrentEnroll();
    void CancelCurrentEnrollIfExist();
    std::mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_IDM_SERVICE_H