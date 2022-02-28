/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef USERAUTH_SERVICE_H
#define USERAUTH_SERVICE_H

#include <iremote_stub.h>
#include <system_ability.h>
#include <system_ability_definition.h>
#include <string>

#include "userauth_stub.h"
#include "userauth_controller.h"
#include "iuser_auth.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuthService : public UserAuthStub, public SystemAbility {
public:
    DECLARE_SYSTEM_ABILITY(UserAuthService);
    explicit UserAuthService(int32_t systemAbilityId, bool runOnCreate = false);
    ~UserAuthService() override;
    void OnStart() override;
    void OnStop() override;
    int32_t GetAvailableStatus(const AuthType authType, const AuthTurstLevel authTurstLevel) override;
    void GetProperty(const GetPropertyRequest request, sptr<IUserAuthCallback>& callback) override;
    void SetProperty(const SetPropertyRequest request, sptr<IUserAuthCallback>& callback) override;
    uint64_t Auth(const uint64_t challenge, const AuthType authType, const AuthTurstLevel authTurstLevel,
                  sptr<IUserAuthCallback>& callback) override;
    uint64_t AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
                      const AuthTurstLevel authTurstLevel, sptr<IUserAuthCallback>& callback) override;
    int32_t CancelAuth(const uint64_t contextId) override;
    int32_t GetVersion() override;

private:
    int32_t GetCallingUserID(int32_t &userID);
    bool CheckPermission(const std::string &permission);
    int32_t GetControllerData(sptr<IUserAuthCallback>& callback, AuthResult &extraInfo,
                              const AuthTurstLevel authTurstLevel, uint64_t &callerID,
                              std::string &callerName, uint64_t &contextID);
    class UserAuthServiceCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        UserAuthServiceCallbackDeathRecipient(sptr<IUserAuthCallback>& impl);
        ~UserAuthServiceCallbackDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        sptr<IUserAuthCallback> callback_ { nullptr };
        DISALLOW_COPY_AND_MOVE(UserAuthServiceCallbackDeathRecipient);
    };
    UserAuthController userauthController_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USERAUTH_SERVICE_H
