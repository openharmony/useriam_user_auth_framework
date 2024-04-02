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
#include "context_appstate_observer.h"

#include <sstream>

#include "context_pool.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "system_ability_definition.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::AppExecFwk;
sptr<IAppMgr> ContextAppStateObserverManager::GetAppManagerInstance()
{
    IAM_LOGI("start");
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        IAM_LOGE("systemAbilityManager is nullptr");
        return nullptr;
    }

    sptr<IRemoteObject> object = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (object == nullptr) {
        IAM_LOGE("systemAbilityManager remote object is nullptr");
        return nullptr;
    }

    return iface_cast<IAppMgr>(object);
}

void ContextAppStateObserverManager::SubscribeAppState(const std::shared_ptr<ContextCallback> &callback,
    const uint64_t contextId)
{
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    const std::string bundleName = callback->GetCallerName();
    if (bundleName.empty()) {
        IAM_LOGE("bundleName is null");
        return;
    }

    sptr<IAppMgr> appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        IAM_LOGE("GetAppManagerInstance failed");
        return;
    }
                        
    appStateObserver_ = new (std::nothrow) ContextAppStateObserver(contextId, bundleName);
    if (appStateObserver_ == nullptr) {
        IAM_LOGE("get appStateObserver failed");
        return;
    }

    std::vector<std::string> bundleNameList;
    bundleNameList.emplace_back(bundleName);
    int32_t result = appManager->RegisterApplicationStateObserver(appStateObserver_, bundleNameList);
    if (result != SUCCESS) {
        IAM_LOGE("RegistApplicationStateObserver failed");
        appStateObserver_ = nullptr;
        return;
    }

    IAM_LOGI("SubscribeAppState success, contextId:****%{public}hx, bundleName:%{public}s",
        static_cast<uint16_t>(contextId), bundleName.c_str());
    return;
}

void ContextAppStateObserverManager::UnSubscribeAppState()
{
    IAM_LOGI("start");
    if (appStateObserver_ == nullptr) {
        IAM_LOGE("appStateObserver_ is nullptr");
        return;
    }

    sptr<IAppMgr> appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        IAM_LOGE("GetAppManagerInstance failed");
        return;
    }

    int32_t result = appManager->UnregisterApplicationStateObserver(appStateObserver_);
    if (result != SUCCESS) {
        IAM_LOGE("UnregisterApplicationStateObserver failed");
        return;
    }

    appStateObserver_ = nullptr;
    IAM_LOGI("UnSubscribeAppState success");
    return;
}

ContextAppStateObserver::ContextAppStateObserver(const uint64_t contextId,
    const std::string bundleName) : contextId_(contextId), bundleName_(bundleName)
{
    IAM_LOGI("start");
}

void ContextAppStateObserver::ProcAppStateChanged()
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

void ContextAppStateObserver::OnAppStateChanged(const AppStateData &appStateData)
{
    IAM_LOGI("start, contextId: ****%{public}hx", static_cast<uint16_t>(contextId_));
    auto bundleName = appStateData.bundleName;
    auto state = static_cast<ApplicationState>(appStateData.state);
    IAM_LOGI("OnAppStateChanged, bundleName:%{public}s, state:%{public}d", bundleName.c_str(), state);

    if (bundleName.compare(bundleName_) == 0 && state == ApplicationState::APP_STATE_BACKGROUND) {
        ProcAppStateChanged();
    }
    return;
}

void ContextAppStateObserver::OnForegroundApplicationChanged(const AppStateData &appStateData)
{
    IAM_LOGI("start, contextId: ****%{public}hx", static_cast<uint16_t>(contextId_));
    auto bundleName = appStateData.bundleName;
    auto state = static_cast<ApplicationState>(appStateData.state);
    IAM_LOGI("OnForegroundApplicationChanged, bundleName:%{public}s, state:%{public}d", bundleName.c_str(), state);

    if (bundleName.compare(bundleName_) == 0 && state == ApplicationState::APP_STATE_BACKGROUND) {
        ProcAppStateChanged();
    }
    return;
}

void ContextAppStateObserver::OnAbilityStateChanged(const AbilityStateData &abilityStateData)
{
    IAM_LOGI("start, contextId: ****%{public}hx", static_cast<uint16_t>(contextId_));
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
