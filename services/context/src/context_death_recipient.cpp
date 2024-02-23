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
#include "context_death_recipient.h"

#include <sstream>

#include "context_pool.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
ContextDeathRecipient::ContextDeathRecipient(uint64_t contextId)
    : contextId_(contextId)
{
    IAM_LOGI("start");
}

void ContextDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }

    auto context = ContextPool::Instance().Select(contextId_).lock();
    if (context == nullptr) {
        IAM_LOGE("context is nullptr");
        return;
    }

    if (!context->Stop()) {
        IAM_LOGE("failed to cancel enroll or auth");
        return;
    }
    return;
}

IamApplicationStateObserver::IamApplicationStateObserver(const uint64_t contextId,
    const std::string bundleName) : contextId_(contextId), bundleName_(bundleName)
{
    IAM_LOGI("start");
}


void IamApplicationStateObserver::ProcAppStateChanged()
{
    IAM_LOGI("start");
    auto context = ContextPool::Instance().Select(contextId_).lock();
    if (context == nullptr) {
        IAM_LOGE("context is nullptr");
        return;
    }
    if (!context->Stop()) {
        IAM_LOGE("failed to cancel enroll or auth");
        return;
    }
    return;
}

void IamApplicationStateObserver::OnAppStateChanged(const AppStateData &appStateData)
{
    IAM_LOGI("start");
    auto bundleName = appStateData.bundleName;
    auto state = static_cast<ApplicationState>(appStateData.state);
    IAM_LOGI("OnAppStateChanged, bundleName:%{public}s, state:%{public}d", bundleName.c_str(), state);

    if (bundleName.compare(bundleName_) == 0 && state == ApplicationState::APP_STATE_BACKGROUND) {
        ProcAppStateChanged();
    }
    return;
}

void IamApplicationStateObserver::OnForegroundApplicationChanged(const AppStateData &appStateData)
{
    IAM_LOGI("start");

    auto bundleName = appStateData.bundleName;
    auto state = static_cast<ApplicationState>(appStateData.state);
    IAM_LOGI("OnForegroundApplicationChanged, bundleName:%{public}s, state:%{public}d", bundleName.c_str(), state);

    if (bundleName.compare(bundleName_) == 0 && state == ApplicationState::APP_STATE_BACKGROUND) {
        ProcAppStateChanged();
    }
    return;
}

void IamApplicationStateObserver::OnAbilityStateChanged(const AbilityStateData &abilityStateData)
{
    IAM_LOGI("start");
    auto bundleName = abilityStateData.bundleName;
    auto state = static_cast<AbilityState>(abilityStateData.abilityState);
    IAM_LOGI("OnAbilityStateChanged, bundleName:%{public}s, state:%{public}d", bundleName.c_str(), state);

    if (bundleName.compare(bundleName_) == 0 && state == AbilityState::ABILITY_STATE_BACKGROUND) {
        ProcAppStateChanged();
    }
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
