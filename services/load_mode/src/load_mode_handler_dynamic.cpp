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

#include "load_mode_handler_dynamic.h"

#include "system_ability_definition.h"

#include "driver_load_manager.h"
#include "driver_state_manager.h"
#include "iam_logger.h"
#include "os_account_manager.h"
#include "service_unload_manager.h"
#include "system_param_manager.h"
#include "user_idm_database.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CredentialUpdatedListener : public EventFwk::CommonEventSubscriber,
    public std::enable_shared_from_this<CredentialUpdatedListener> {
public:
    explicit CredentialUpdatedListener(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        : EventFwk::CommonEventSubscriber(subscribeInfo) {}
    ~CredentialUpdatedListener() = default;
    
    void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override
    {
        IAM_LOGI("start");
        const EventFwk::Want &want = eventData.GetWant();
        std::string action = want.GetAction();
        if (action != "USER_CREDENTIAL_UPDATED_EVENT") {
            return;
        }
        IAM_LOGI("receive event %{public}s", action.c_str());
        std::string authType = want.GetStringParam("authType");
        LoadModeHandler::GetInstance().OnCredentialUpdated(authType);
    }
};

LoadModeHandlerDynamic::LoadModeHandlerDynamic()
{
    IAM_LOGI("sa load mode is dynamic");
    
    SubscribeCommonEventServiceListener();
    
    DriverStateManager::GetInstance().RegisterDriverStartCallback([this]() {
        this->OnDriverStart();
    });
    DriverStateManager::GetInstance().RegisterDriverStopCallback([this]() {
        this->OnDriverStop();
    });
}

void LoadModeHandlerDynamic::SubscribeCredentialUpdatedListener()
{
    IAM_LOGI("start");
    EventFwk::MatchingSkills matchSkills;
    matchSkills.AddEvent("USER_CREDENTIAL_UPDATED_EVENT");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchSkills);
    if (credentialUpdatedListener_ == nullptr) {
        credentialUpdatedListener_ = std::make_shared<CredentialUpdatedListener>(subscribeInfo);
    }
    IF_FALSE_LOGE_AND_RETURN(credentialUpdatedListener_ != nullptr);
    bool subscribeRet = EventFwk::CommonEventManager::SubscribeCommonEvent(credentialUpdatedListener_);
    IF_FALSE_LOGE_AND_RETURN(subscribeRet == true);
}

void LoadModeHandlerDynamic::SubscribeCommonEventServiceListener()
{
    IAM_LOGI("enter");
    commonEventServiceListener_ = SystemAbilityListener::Subscribe(
        "CommonEventService", COMMON_EVENT_SERVICE_ID,
        []() {
            GetInstance().OnCommonEventSaStart();
        },
        nullptr);
    IF_FALSE_LOGE_AND_RETURN(commonEventServiceListener_ != nullptr);
}

void LoadModeHandlerDynamic::OnCommonEventSaStart()
{
    SubscribeCredentialUpdatedListener();
    OnCredentialUpdated(PIN);
}

void LoadModeHandlerDynamic::Init()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isInit_) {
        return;
    }

    const auto &driverLoadManager = DriverLoadManager::GetInstance();
    (void)driverLoadManager;
    const auto &serviceUnloadManager = ServiceUnloadManager::GetInstance();
    (void)serviceUnloadManager;

    if (pinAuthServiceListener_ == nullptr) {
        pinAuthServiceListener_ = SystemAbilityListener::Subscribe(
            "PinAuthService", SUBSYS_USERIAM_SYS_ABILITY_PINAUTH,
            []() { LoadModeHandler::GetInstance().OnPinAuthServiceReady(); },
            []() { LoadModeHandler::GetInstance().OnPinAuthServiceStop(); });
    }

    IAM_LOGI("init load mode handler dynamic success");
    isInit_ = true;
}

void LoadModeHandlerDynamic::OnFwkReady()
{
    IAM_LOGI("fwk ready");
    RefreshIsPinEnrolled();
    SystemParamManager::GetInstance().SetParam(IS_CREDENTIAL_CHECKED_KEY, TRUE_STR);
    bool isStopSa = false;
    ServiceUnloadManager::GetInstance().OnFwkReady(isStopSa);
    if (!isStopSa) {
        SystemParamManager::GetInstance().SetParamTwice(FWK_READY_KEY, FALSE_STR, TRUE_STR);
    }
}

void LoadModeHandlerDynamic::OnExecutorRegistered(AuthType authType, ExecutorRole executorRole)
{
    if (authType != AuthType::PIN || executorRole != ExecutorRole::ALL_IN_ONE) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("executor registered authType %{public}d, executorRole %{public}d", authType, executorRole);
    isExecutorRegistered_ = true;
    RefreshIsPinFunctionReady();
}

void LoadModeHandlerDynamic::OnExecutorUnregistered(AuthType authType, ExecutorRole executorRole)
{
    if (authType != AuthType::PIN || executorRole != ExecutorRole::ALL_IN_ONE) {
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("executor unregistered authType %{public}d, executorRole %{public}d", authType, executorRole);
    isExecutorRegistered_ = false;
    RefreshIsPinFunctionReady();
}

void LoadModeHandlerDynamic::OnPinAuthServiceReady()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("on pin auth service ready");
    isPinAuthServiceReady_ = true;
    RefreshIsPinFunctionReady();
}

void LoadModeHandlerDynamic::OnPinAuthServiceStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("on pin auth service stop");
    isPinAuthServiceReady_ = false;

    RefreshIsPinFunctionReady();
    bool isPinEnrolled = SystemParamManager::GetInstance().GetParam(IS_PIN_ENROLLED_KEY, FALSE_STR) == TRUE_STR;
    if (isPinEnrolled) {
        IAM_LOGI("pin auth service down, pin enrolled, wait fwk ready");
    } else {
        bool isStopSa = SystemParamManager::GetInstance().GetParam(STOP_SA_KEY, FALSE_STR) == TRUE_STR;
        if (isStopSa) {
            IAM_LOGI("Sa is stopping, not need stop sa");
        } else {
            IAM_LOGI("pin auth service down, pin not enrolled, stop sa");
            SystemParamManager::GetInstance().SetParamTwice(STOP_SA_KEY, FALSE_STR, TRUE_STR);
        }
    }
}

void LoadModeHandlerDynamic::RefreshIsPinFunctionReady()
{
    bool isPinFunctionReady = isExecutorRegistered_ && isPinAuthServiceReady_;
    IAM_LOGI("is pin function ready %{public}s", isPinFunctionReady ? TRUE_STR : FALSE_STR);
    SystemParamManager::GetInstance().SetParam(IS_PIN_FUNCTION_READY_KEY, isPinFunctionReady ? TRUE_STR : FALSE_STR);
}

void LoadModeHandlerDynamic::OnCredentialUpdated(AuthType authType)
{
    if (authType != AuthType::PIN) {
        return;
    }
    IAM_LOGI("on credential deleted authType %{public}d", authType);
    RefreshIsPinEnrolled();
}

bool LoadModeHandlerDynamic::AnyUserHasPinCredential()
{
    std::vector<AccountSA::OsAccountInfo> osAccountInfo;
    ErrCode errCode = AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfo);
    if (errCode != ERR_OK) {
        IAM_LOGE("QueryAllCreatedOsAccounts fail, errCode = %{public}d", errCode);
        return false;
    }

    for (auto &info : osAccountInfo) {
        int32_t userId = info.GetLocalId();
        std::vector<std::shared_ptr<CredentialInfoInterface>> credInfos;
        int32_t getCredRet = UserIdmDatabase::Instance().GetCredentialInfo(userId, AuthType::PIN, credInfos);
        if (getCredRet != SUCCESS) {
            // it's possible that the user has no credential
            IAM_LOGI("failed to get credential info ret %{public}d", getCredRet);
            continue;
        }

        if (!credInfos.empty()) {
            IAM_LOGI("user %{public}d pin credential number %{public}zu", userId, credInfos.size());
            return true;
        }
        IAM_LOGI("user %{public}d has no pin credential", userId);
    }
    return false;
}

void LoadModeHandlerDynamic::RefreshIsPinEnrolled()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isPinEnrolled_ = AnyUserHasPinCredential();
    IAM_LOGI("is pin enrolled %{public}s", isPinEnrolled_ ? TRUE_STR : FALSE_STR);

    SystemParamManager::GetInstance().SetParam(IS_PIN_ENROLLED_KEY, isPinEnrolled_ ? TRUE_STR : FALSE_STR);
}

void LoadModeHandlerDynamic::OnDriverStart()
{
    IAM_LOGI("on driver start");
    DriverLoadManager::GetInstance().OnDriverStart();
}

void LoadModeHandlerDynamic::OnDriverStop()
{
    IAM_LOGI("on driver stop");
    DriverLoadManager::GetInstance().OnDriverStop();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
