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
#include "iam_logger.h"
#include "os_account_manager.h"
#include "service_unload_manager.h"
#include "system_param_manager.h"
#include "user_idm_database.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
LoadModeHandlerDynamic::LoadModeHandlerDynamic()
{
    IAM_LOGI("sa load mode is dynamic");
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

void LoadModeHandlerDynamic::OnCredentialEnrolled(AuthType authType)
{
    if (authType != AuthType::PIN) {
        return;
    }
    IAM_LOGI("on credential enrolled authType %{public}d", authType);
    RefreshIsPinEnrolled();
}

void LoadModeHandlerDynamic::OnCredentialDeleted(AuthType authType)
{
    if (authType != AuthType::PIN) {
        return;
    }
    IAM_LOGI("on credential deleted authType %{public}d", authType);
    RefreshIsPinEnrolled();
}

bool LoadModeHandlerDynamic::AnyUserHasPinCredential()
{
    std::vector<AccountSA::OsAccountInfo> OsAccountInfo;
    ErrCode errCode = AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos);
    if (errCode != ERR_OK) {
        IAM_LOGE("QueryAllCreatedOsAccounts fail, errCode = %{public}d", errCode);
        return false;
    }

    std::vector<int32_t> allCreatedUserId;
    for (auto &info : osAccountInfos) {
        allCreatedUserId.push_back(info.GetLocal());
    }

    for (int32_t userId : allCreatedUserId) {
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
