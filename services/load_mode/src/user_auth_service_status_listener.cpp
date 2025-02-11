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

#include "user_auth_service_status_listener.h"

#include "iservice_registry.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth{
UserAuthServicesStatusListener::UserAuthServicesStatusListener(std::string name, int32_t systemAbilityId,
    AddFunc addFunc, RemoveFunc removeFunc)
    : name_(name), systemAbilityId_(systemAbilityId), addFunc_(addFunc), removeFunc_(removeFunc)
{
    IAM_LOGI("ServiceStatusListener %{public}s get", name_.c_str());
}

void UserAuthServicesStatusListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != systemAbilityId_) {
        return;
    }

    IAM_LOGI("%{public}s AddFunc called", name_.c_str());
    if (addFunc_ != nullptr) {
        addFunc_();
    }
}

void UserAuthServicesStatusListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != systemAbilityId_) {
        return;
    }

    IAM_LOGI("%{public}s RemoveFunc called", name_.c_str());
    if (removeFunc_ != nullptr) {
        removeFunc_();
    }
}

sptr<UserAuthServicesStatusListener> UserAuthServicesStatusListener::Subscribe(
    std::string name, int32_t systemAbilityId, AddFunc addFunc, RemoveFunc removeFunc)
{
    IAM_LOGI("start name:%{public}s systemAbilityId:%{public}d", name.c_str(), systemAbilityId);
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    IF_FALSE_LOGE_AND_RETURN_VAL(sam != nullptr, nullptr);

    sptr<UserAuthServicesStatusListener> listener(
        new (std::nothrow) UserAuthServicesStatusListener(name, systemAbilityId, addFunc, removeFunc));
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, nullptr);

    int32_t ret = sam->SubscribeSystemAbility(systemAbilityId, listener);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, nullptr);
    if (ret != ERR_OK) {
        IAM_LOGE("fail to subscribe service %{public}s status %{public}d", name.c_str(), ret);
        return nullptr;
    }
    IAM_LOGI("subscribe service %{public}s status success", name.c_str());
    return listener;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS