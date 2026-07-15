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

#ifndef ENGINE_LOAD_MANAGER_H
#define ENGINE_LOAD_MANAGER_H

#include <mutex>

#include <optional>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EngineLoadManager {
public:
    static EngineLoadManager &GetInstance();

    void StartSubscribe();
    void OnTimeout();
    void OnEngineReady();
    void OnEngineUnavailable();

    void OnSaStopping(bool isStopping);

private:
    EngineLoadManager() = default;
    ~EngineLoadManager() = default;

    void ProcessServiceStatus();
    bool Load();
    bool Unload();

    bool isSubscribed_ = false;
    std::recursive_mutex mutex_;
    bool isEngineRunning_ = false;
    bool isSaStopping_ = false;
    std::optional<int32_t> timerId_ = std::nullopt;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // ENGINE_LOAD_MANAGER_H