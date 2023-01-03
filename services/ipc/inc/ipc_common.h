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

#ifndef IPC_COMMON_H
#define IPC_COMMON_H

#include <cinttypes>
#include <iremote_stub.h>
#include <optional>
#include <string>

#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum Permission {
    MANAGE_USER_IDM_PERMISSION,
    USE_USER_IDM_PERMISSION,
    ACCESS_USER_AUTH_INTERNAL_PERMISSION,
    ACCESS_BIOMETRIC_PERMISSION,
    ACCESS_AUTH_RESPOOL,
    ENFORCE_USER_IDM,
};

class IpcCommon final : public NoCopyable {
public:
    using Recipient = std::function<void()>;
    static int32_t GetCallingUserId(IPCObjectStub &stub, int32_t &userId);
    static int32_t GetActiveUserId(std::optional<int32_t> &userId);
    static bool CheckPermission(IPCObjectStub &stub, Permission permission);
    static uint32_t GetAccessTokenId(IPCObjectStub &stub);
    class PeerDeathRecipient final : public IPCObjectProxy::DeathRecipient {
    public:
        explicit PeerDeathRecipient(Recipient &&recipient) : recipient_(std::forward<Recipient>(recipient))
        {
        }
        ~PeerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &object) override
        {
            if (auto remote = object.promote(); !remote) {
                return;
            }
            if (recipient_) {
                recipient_();
            }
        };

    private:
        Recipient recipient_;
    };

private:
    static bool CheckNativeCallingProcessWhiteList(IPCObjectStub &stub);
    static bool CheckDirectCallerAndFirstCallerIfSet(IPCObjectStub &stub, const std::string &permission);
    static bool CheckDirectCaller(IPCObjectStub &stub, const std::string &permission);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IPC_COMMON_H