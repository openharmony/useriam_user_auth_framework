/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef REMOTE_AUTH_CALLBACK_MANAGER
#define REMOTE_AUTH_CALLBACK_MANAGER

#include <memory>
#include <mutex>
#include <unordered_map>

#include "iremote_object.h"
#include "refbase.h"

#include "iam_common_defines.h"
#include "iremote_auth_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteAuthCallbackManager {
public:
    static RemoteAuthCallbackManager &GetInstance();
    int32_t AddRemoteAuthCallback(uint32_t tokenId, const sptr<IRemoteAuthCallback> &remoteAuthCallback);
    void DelRemoteAuthCallback(uint32_t tokenId);
    sptr<IRemoteAuthCallback> GetRemoteAuthCallback(uint32_t tokenId);
    std::string GetRemoteAuthCallerName(uint32_t tokenId);

private:
    RemoteAuthCallbackManager();
    ~RemoteAuthCallbackManager() = default;

    std::unordered_map<uint32_t, sptr<IRemoteAuthCallback>> callbackMap_;
    std::unordered_map<uint32_t, sptr<IRemoteObject::DeathRecipient>> remoteDeathMap_;
    std::mutex mutex_;

    class RemoteAuthCallbackDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
        public:
            explicit RemoteAuthCallbackDeathRecipient(uint32_t tokenId);
            ~RemoteAuthCallbackDeathRecipient() override = default;
            void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

        private:
            uint32_t tokenId_;
    };
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_AUTH_CALLBACK_MANAGER