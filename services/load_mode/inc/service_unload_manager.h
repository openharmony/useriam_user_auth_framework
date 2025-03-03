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

#ifndef SERVICE_UNLOAD_MANAGER_H
#define SERVICE_UNLOAD_MANAGER_H

#include <mutex>
#include <optional>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ServiceUnloadManager {
public:
    static ServiceUnloadManager &GetInstance();
    void OnTimeout();
    void OnIsPinEnrolledChange(bool isPinEnrolled);
    void OnStartSaChange(bool startSa);
    void OnFwkReady(bool &isStopSa);
    void StartSubscribe();

private:
    ServiceUnloadManager() = default;
    ~ServiceUnloadManager() = default;
    void RestartTimer();
    void StopTimer();

    std::recursive_mutex mutex_;
    bool isSubscribed_ = false;
    std::optional<int32_t> timerId_ = std::nullopt;
    bool isPinEnrolled_ = false;
    bool startSa_ = false;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // SERVICE_UNLOAD_MANAGER_H