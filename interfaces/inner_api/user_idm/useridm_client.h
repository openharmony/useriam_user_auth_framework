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

#ifndef USERIDM_CLIENT_H
#define USERIDM_CLIENT_H

#include <iremote_object.h>
#include <singleton.h>
#include "iuser_idm.h"
#include "useridm_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMClient : public DelayedRefSingleton<UserIDM::UserIDMClient> {
    DECLARE_DELAYED_REF_SINGLETON(UserIDMClient);

public:
    DISALLOW_COPY_AND_MOVE(UserIDMClient);

    /**
     * the user id that can be used for getting all credential info
     */
    static const int32_t ALL_INFO_GET_USER_ID = -1;
    uint64_t OpenSession();
    void CloseSession();
    int32_t GetAuthInfo(AuthType authType, const std::shared_ptr<GetInfoCallback>& callback);
    int32_t GetAuthInfo(int32_t userId, AuthType authType, const std::shared_ptr<GetInfoCallback>& callback);
    int32_t GetSecInfo(int32_t userId, const std::shared_ptr<GetSecInfoCallback>& callback);
    void AddCredential(AddCredInfo& credInfo, const std::shared_ptr<IDMCallback>& callback);
    void UpdateCredential(AddCredInfo& credInfo, const std::shared_ptr<IDMCallback>& callback);
    int32_t Cancel(uint64_t challenge);
    int32_t EnforceDelUser(int32_t userId, const std::shared_ptr<IDMCallback>& callback);
    void DelUser(std::vector<uint8_t> authToken, const std::shared_ptr<IDMCallback>& callback);
    void DelCred(uint64_t credentialId, std::vector<uint8_t> authToken, const std::shared_ptr<IDMCallback>& callback);

private:
    class UserIDMDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        UserIDMDeathRecipient() = default;
        ~UserIDMDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(UserIDMDeathRecipient);
    };

    void ResetUserIDMProxy(const wptr<IRemoteObject>& remote);
    sptr<IUserIDM> GetUserIDMProxy();

    std::mutex mutex_;
    sptr<IUserIDM> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS

#endif // USERIDM_CLIENT_H
