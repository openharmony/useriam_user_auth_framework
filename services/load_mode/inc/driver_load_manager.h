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

#ifndef DRIVER_LOAD_MANAGER_H
#define DRIVER_LOAD_MANAGER_H

#include <mutex>

#include "iservstat_listener_hdi.h"
#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using ServStatListenerStub = HDI::ServiceManager::V1_0::ServStatListenerStub;
class DriverLoadManager {
public:
    static DriverLoadManager &GetInstance();

    void Init();
    void OnTimeout();
    void OnDriverStart();
    void OnDriverStop();

    void OnSaStopping(bool isStopping);

private:
    DriverLoadManager() = default;
    ~DriverLoadManager() = default;

    void ProcessServiceStatus();
    bool LoadDriver();
    bool UnloadDriver();

    bool isInit_ = false;
    std::recursive_mutex mutex_;
    sptr<SystemAbilityListener> driverManagerStatusListener_ = nullptr;
    sptr<ServStatListenerStub> driverStatusListener_ = nullptr;
    bool isDriverRunning_ = false;
    bool isSaStopping_ = false;
    std::optional<int32_t> timerId_ = std::nullopt;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // DRIVER_LOAD_MANAGER_H