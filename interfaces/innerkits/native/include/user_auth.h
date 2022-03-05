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

#ifndef USERAUTH_CLIENT_H
#define USERAUTH_CLIENT_H

#include <iremote_object.h>
#include <mutex>
#include <singleton.h>

#include "iuser_auth.h"
#include "userauth_async_stub.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuth : public DelayedRefSingleton<UserAuth> {
    DECLARE_DELAYED_REF_SINGLETON(UserAuth);

public:
    DISALLOW_COPY_AND_MOVE(UserAuth);

    int32_t GetAvailableStatus(const AuthType authType, const AuthTurstLevel authTurstLevel);
    void GetProperty(const GetPropertyRequest request, std::shared_ptr<GetPropCallback> callback);
    void SetProperty(const SetPropertyRequest request, std::shared_ptr<SetPropCallback> callback);
    uint64_t Auth(const uint64_t challenge, const AuthType authType, const AuthTurstLevel authTurstLevel,
        std::shared_ptr<UserAuthCallback> callback);
    uint64_t AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
        const AuthTurstLevel authTurstLevel, std::shared_ptr<UserAuthCallback> callback);
    int32_t CancelAuth(const uint64_t contextId);
    int32_t GetVersion();

private:
    class UserAuthDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        UserAuthDeathRecipient() = default;
        ~UserAuthDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(UserAuthDeathRecipient);
    };
    void ResetProxy(const wptr<IRemoteObject> &remote);
    sptr<IUserAuth> GetProxy();

    std::mutex mutex_;
    sptr<IUserAuth> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // USERAUTH_CLIENT_H
