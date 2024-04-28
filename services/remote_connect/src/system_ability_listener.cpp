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

#include "system_ability_listener.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
SystemAbilityListener::SystemAbilityListener(std::string name, int32_t systemAbilityId,
    AddFunc addFunc, RemoveFunc removeFunc)
    : name_(name), systemAbilityId_(systemAbilityId), addFunc_(addFunc), removeFunc_(removeFunc)
{
    IAM_LOGI("start.");
}

void SystemAbilityListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    IAM_LOGI("start.");
    if (systemAbilityId != systemAbilityId_) {
        IAM_LOGI("systemAbilityId is not same.");
        return;
    }

    if (addFunc_ != nullptr) {
        addFunc_();
        IAM_LOGI("addFunc_ proc.");
    }
}
    
void SystemAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    IAM_LOGI("start.");
    if (systemAbilityId != systemAbilityId_) {
        IAM_LOGI("systemAbilityId is not same.");
        return;
    }

    if (removeFunc_ != nullptr) {
        removeFunc_();
        IAM_LOGI("removeFunc_ proc.");
    }
}

DeviceManagerListener::DeviceManagerListener(std::string name, int32_t systemAbilityId,
    AddFunc addFunc, RemoveFunc removeFunc)
    : SystemAbilityListener(name, systemAbilityId, addFunc, removeFunc)
{
    IAM_LOGI("start.");
}

SoftBusListener::SoftBusListener(std::string name, int32_t systemAbilityId,
    AddFunc addFunc, RemoveFunc removeFunc)
    : SystemAbilityListener(name, systemAbilityId, addFunc, removeFunc)
{
    IAM_LOGI("start.");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
