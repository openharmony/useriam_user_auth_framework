/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IAM_CONTEXT_DEAD_RECIPIENT_H
#define IAM_CONTEXT_DEAD_RECIPIENT_H

#include <cstdint>
#include <string>

#include "application_state_observer_stub.h"
#include "app_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::AppExecFwk;
class ContextDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        ContextDeathRecipient(uint64_t contextId);
        ~ContextDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    protected:
        uint64_t contextId_;
};

class IamApplicationStateObserver : public ApplicationStateObserverStub {
    public:
        IamApplicationStateObserver(const uint64_t contextId, const std::string bundleName);
        ~IamApplicationStateObserver() override = default;
        void OnAppStateChanged(const AppStateData &appStateData) override;
        void OnForegroundApplicationChanged(const AppStateData &appStateData) override;
        void OnAbilityStateChanged(const AbilityStateData &abilityStateData) override;
    protected:
        void ProcAppStateChanged();
        const uint64_t contextId_;
        const std::string bundleName_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_DEAD_RECIPIENT_H