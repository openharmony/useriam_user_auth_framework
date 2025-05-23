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

#ifndef CO_AUTH_CLIENT_IMPL_H
#define CO_AUTH_CLIENT_IMPL_H

#include <mutex>

#include "nocopyable.h"

#include "ico_auth.h"
#include "co_auth_client.h"
#include "co_auth_interface.h"
#include "user_auth_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthClientImpl final : public CoAuthClient, public NoCopyable {
public:
    uint64_t Register(const ExecutorInfo &info, const std::shared_ptr<ExecutorRegisterCallback> &callback) override;
    void Unregister(uint64_t executorIndex) override;

private:
    friend class CoAuthClient;
    CoAuthClientImpl() = default;
    ~CoAuthClientImpl() override = default;
    static CoAuthClientImpl &Instance();
    void InitIpcExecutorInfo(const ExecutorInfo &info, IpcExecutorRegisterInfo &ipcExecutorRegisterInfo);
    class CoAuthImplDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        CoAuthImplDeathRecipient() = default;
        ~CoAuthImplDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    void ResetProxy(const wptr<IRemoteObject> &remote);
    sptr<ICoAuth> GetProxy();
    sptr<ICoAuth> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
    std::mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_CLIENT_IMPL_H