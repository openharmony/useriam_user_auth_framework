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
#include "base_context.h"

#include <sstream>

#include "context_death_recipient.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "system_ability_definition.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
BaseContext::BaseContext(const std::string &type, uint64_t contextId, std::shared_ptr<ContextCallback> callback)
    : callback_(callback),
      contextId_(contextId)
{
    std::ostringstream ss;
    ss << "Context(type:" << type << ", contextId:" << GET_MASKED_STRING(contextId_) << ")";
    description_ = ss.str();
}

void BaseContext::SetLatestError(int32_t error)
{
    if (error != ResultCode::SUCCESS) {
        latestError_ = error;
    }
}

int32_t BaseContext::GetLatestError() const
{
    return latestError_;
}

uint64_t BaseContext::GetContextId() const
{
    return contextId_;
}

sptr<IRemoteObject::DeathRecipient> BaseContext::GetDeathRecipient() const
{
    return deathRecipient_;
}

sptr<ApplicationStateObserverStub> BaseContext::GetAppStateObserver() const
{
    return appStateObserver_;
}

bool BaseContext::Start()
{
    std::lock_guard<std::mutex> guard(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());
    if (hasStarted_) {
        IAM_LOGI("%{public}s context has started, cannot start again", GetDescription());
        return false;
    }
    AddDeathrecipient();
    SubscribeAppState();
    hasStarted_ = true;
    return OnStart();
}

bool BaseContext::Stop()
{
    IAM_LOGI("%{public}s start", GetDescription());
    RemoveDeathrecipient();
    UnSubscribeAppState();
    return OnStop();
}

std::shared_ptr<ScheduleNode> BaseContext::GetScheduleNode(uint64_t scheduleId) const
{
    for (auto const &schedule : scheduleList_) {
        if (schedule == nullptr) {
            continue;
        }
        if (schedule->GetScheduleId() == scheduleId) {
            return schedule;
        }
    }
    return nullptr;
}

void BaseContext::OnScheduleStarted()
{
    IAM_LOGI("%{public}s start", GetDescription());
}

void BaseContext::OnScheduleProcessed(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg)
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    callback_->OnAcquireInfo(src, moduleType, acquireMsg);
}

void BaseContext::OnScheduleStoped(int32_t resultCode, const std::shared_ptr<Attributes> &finalResult)
{
    OnResult(resultCode, finalResult);
    RemoveDeathrecipient();
    UnSubscribeAppState();
    return;
}

const char *BaseContext::GetDescription() const
{
    return description_.c_str();
}

void BaseContext::AddDeathrecipient()
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    const sptr<IamCallbackInterface> &callback = callback_->GetIamCallback();
    if (callback == nullptr) {
        IAM_LOGE("callback_ is nullptr");
        return;
    }
    auto obj = callback->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return;
    }

    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow)ContextDeathRecipient(GetContextId()));
    if ((dr == nullptr) || (!obj->AddDeathRecipient(dr))) {
        IAM_LOGE("AddDeathRecipient failed");
        return;
    }

    deathRecipient_ = dr;
    return;
}

void BaseContext::RemoveDeathrecipient()
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    if (deathRecipient_ == nullptr) {
        IAM_LOGE("deathRecipient_ is nullptr");
        return;
    }

    const sptr<IamCallbackInterface> &callback = callback_->GetIamCallback();
    if (callback == nullptr) {
        IAM_LOGE("callback_ is nullptr");
        return;
    }

    auto obj = callback->AsObject();
    if (obj == nullptr) {
        IAM_LOGE("remote object is nullptr");
        return;
    }

    obj->RemoveDeathRecipient(deathRecipient_);
    deathRecipient_ = nullptr;
    return;
}

sptr<IAppMgr> BaseContext::GetAppManagerInstance()
{
    IAM_LOGI("%{public}s start", GetDescription());
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        IAM_LOGE("systemAbilityManager is nullptr");
    }

    sptr<IRemoteObject> object = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (object == nullptr) {
        IAM_LOGE("systemAbilityManager remote object is nullptr");
    }

    return iface_cast<IAppMgr>(object);
}

void BaseContext::SubscribeAppState()
{
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    const std::string bundleName = callback_->GetCallerName();
    if (bundleName.empty()) {
        IAM_LOGE("bundleName is null");
        return;
    }

    sptr<IAppMgr> appManager = GetAppManagerInstance();
    if (appManager == nullptr) {
        IAM_LOGE("GetAppManagerInstance failed");
        return;
    }

    appStateObserver_ = new (std::nothrow)IamApplicationStateObserver(GetContextId(), bundleName);
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
        static_cast<uint16_t>(GetContextId()), bundleName.c_str());
    return;
}

void BaseContext::UnSubscribeAppState()
{
    IAM_LOGI("%{public}s start", GetDescription());
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
    IAM_LOGI("UnSubscribeAppState success, contextId:****%{public}hx",
        static_cast<uint16_t>(GetContextId()));
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
