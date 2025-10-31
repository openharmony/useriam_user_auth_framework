/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include "screenlock_manager.h"

namespace OHOS {
namespace ScreenLock {
std::mutex ScreenLockManager::instanceLock_;
sptr<ScreenLockManager> ScreenLockManager::instance_;
ScreenLockManager::ScreenLockManager() {}
ScreenLockManager::~ScreenLockManager() {}
int32_t reasonFlag_ = 0;
sptr<ScreenLockManager> ScreenLockManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) ScreenLockManager;
        }
    }
    return instance_;
}

int32_t ScreenLockManager::RequestStrongAuth(int reasonFlag, int32_t userId)
{
    (void)userId;
    reasonFlag_ = reasonFlag;
    return reasonFlag;
}

int32_t ScreenLockManager::GetStrongAuth(int userId, int32_t &reasonFlag)
{
    (void)userId;
    reasonFlag = reasonFlag_;
    return 0;
}
} // namespace ScreenLock
} // namespace OHOS