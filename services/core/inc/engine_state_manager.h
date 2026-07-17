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

#ifndef ENGINE_STATE_MANAGER_H
#define ENGINE_STATE_MANAGER_H

#include <functional>
#include <mutex>
#include <optional>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EngineStateManager {
public:
    static EngineStateManager &GetInstance();
    using EngineUpdateCallback = std::function<void()>;

    void OnEngineReady();
    void OnEngineUnavailable();
    void RegisterEngineReadyCallback(const EngineUpdateCallback &callback);
    void RegisterEngineUnavailableCallback(const EngineUpdateCallback &callback);
    void StartSubscribe();

private:
    EngineStateManager() = default;
    ~EngineStateManager() = default;

    bool isSubscribed_ = false;
    std::recursive_mutex mutex_;
    std::optional<bool> isEngineRunning_ {std::nullopt};
    std::vector<EngineUpdateCallback> startCallbacks_;
    std::vector<EngineUpdateCallback> stopCallbacks_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // ENGINE_STATE_MANAGER_H
