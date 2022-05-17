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

#include "system_ability_status_listener.h"

#include "driver_manager.h"
#include "iam_logger.h"
#include "system_ability_definition.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
std::mutex SystemAbilityStatusListener::mutex_;
sptr<SystemAbilityStatusListener> SystemAbilityStatusListener::instance_ = nullptr;
sptr<SystemAbilityStatusListener> SystemAbilityStatusListener::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> gurard(mutex_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) SystemAbilityStatusListener();
            if (instance_ == nullptr) {
                IAM_LOGE("create instance failed");
            }
        }
    }
    return instance_;
}

void SystemAbilityStatusListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != DEVICE_SERVICE_MANAGER_SA_ID) {
        return;
    }

    IAM_LOGI("device service manager SA added");
    Singleton<DriverManager>::GetInstance().SubscribeHdiDriverStatus();
}

void SystemAbilityStatusListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != DEVICE_SERVICE_MANAGER_SA_ID) {
        return;
    }

    IAM_LOGI("device service manager SA removed");
    // when hdi device manager die, hdi driver status is not reliable, disconnect all
    Singleton<DriverManager>::GetInstance().OnAllHdiDisconnect();
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
