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

#ifndef DRIVER_STATE_MANAGER_H
#define DRIVER_STATE_MANAGER_H

#include <mutex>
#include <optional>

#include "iservstat_listener_hdi.h"
#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using ServStatListenerStub = HDI::ServiceManager::V1_0::ServStatListenerStub;
class DriverStateManager {
public:
    static DriverStateManager &GetInstance();
    using DriverUpdateCallback = std::function<void()>;

    void Init();
    void OnDriverManagerAdd();
    void OnDriverManagerRemove();
    void OnDriverStart();
    void OnDriverStop();
    void RegisterDriverStartCallback(const DriverUpdateCallback& callback);
    void RegisterDriverStopCallback(const DriverUpdateCallback& callback);

private:
    DriverStateManager() = default;
    ~DriverStateManager() = default;

    bool isInit_ = false;
    std::recursive_mutex mutex_;
    sptr<SystemAbilityListener> driverManagerStatusListener_ = nullptr;
    sptr<ServStatListenerStub> driverStatusListener_ = nullptr;
    std::optional<bool> isDriverRunning_ {std::nullopt};
    std::vector<DriverUpdateCallback> startCallbacks_;
    std::vector<DriverUpdateCallback> stopCallbacks_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // DRIVER_STATE_MANAGER_H