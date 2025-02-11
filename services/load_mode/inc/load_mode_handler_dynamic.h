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

#ifndef LOAD_MODE_HANDLER_DYNAMIC_H
#define LOAD_MODE_HANDLER_DYNAMIC_H

#include "load_mode_handler.h"

#include <mutex>
#include <optional>

#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "system_ability_listener.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class LoadModeHandlerDynamic : public LoadModeHandler {
public:
    LoadModeHandlerDynamic();
    ~LoadModeHandlerDynamic() override = default;

    void Init() override;
    void OnFwkReady() override;
    void OnExecutorRegistered(AuthType authType, ExecutorRole executorRole) override;
    void OnExecutorUnregistered(AuthType authType, ExecutorRole executorRole) override;
    void OnCredentialUpdated(AuthType authType) override;
    void OnPinAuthServiceReady() override;
    void OnPinAuthServiceStop() override;
    void OnDriverStart() override;
    void OnDriverStop() override;
    void SubscribeCredentialUpdatedListener() override;
    void OnStartSa() override;
    void SubscribeCommonEventServiceListener();

private:
    bool AnyUserHasPinCredential();
    void RefreshIsPinEnrolled();
    void RefreshIsPinFunctionReady();

    bool isInit_ = false;
    std::recursive_mutex mutex_;
    bool isPinEnrolled_ = false;
    sptr<SystemAbilityListener> pinAuthServiceListener_ = nullptr;
    bool isExecutorRegistered_ = false;
    bool isPinAuthServiceReady_ = false;
    sptr<OHOS::SystemAbilityStatusChangeStub> commonEventServiceListener_ = nullptr;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // LOAD_MODE_HANDLER_DYNAMIC_H