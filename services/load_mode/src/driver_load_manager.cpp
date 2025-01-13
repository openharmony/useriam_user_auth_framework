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

#include "driver_load_manager.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "idevmgr_hdi.h"
#include "iservice_registry.h"
#include "iservmgr_hdi.h"
#include "system_ability_definition.h"

#include "co_auth_service.h"
#include "relative_timer.h"
#include "system_param_manager.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace HDI;
using namespace HDI::ServiceManager::V1_0;
using namespace HDI::DeviceManager::V1_0;
const char *SERVICE_NAME = "user_auth_interface_service";
class DriverManagerStatusListener : public ServStatListenerStub {
public:
    DriverManagerStatusListener() = default;
    ~DriverManagerStatusListener() override = default;

    void OnReceive(const ServiceStatus &status) override
    {
        if (status.serviceName != SERVICE_NAME) {
            return;
        }

        IAM_LOGI("receive service %{public}s status %{public}d", status.serviceName.c_str(), status.status);
        if (status.status == SERVIE_STATUS_START) {
            DriverLoadManager::GetInstance().OnServiceStart();
        } else if (status.status == SERVIE_STATUS_STOP) {
            DriverLoadManager::GetInstance().OnServiceStop();
        }
    }
};

DriverLoadManager &DriverLoadManager::GetInstance()
{
    static DriverLoadManager instance;
    instance.Init();
    return instance;
}

void DriverLoadManager::Init()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (isInit_) {
        return;
    }

    if (driverManagerStatusListener_ == nullptr) {
        driverManagerStatusListener_ = SystemAbilityListener::Subscribe(
            "DriverLoadManager", DEVICE_SERVICE_MANAGER_SA_ID,
            []() { DriverLoadManager::GetInstance().OnDriverManagerAdd(); }, nullptr);
        IF_FALSE_LOGE_AND_RETURN(driverManagerStatusListener_ != nullptr);
    }

    if (driverStatusListener_ == nullptr) {
        driverStatusListener_ = new (std::nothrow) DriverManagerStatusListener();
        IF_FALSE_LOGE_AND_RETURN(driverStatusListener_ != nullptr);
    }

    SystemParamManager::GetInstance().WatchParam(STOP_SA_KEY, [](const std::string &value) {
        IAM_LOGI("%{public}s changed, value %{public}s", STOP_SA_KEY, value.c_str());
        DriverLoadManager::GetInstance().OnSaStopping(value == TRUE_STR);
    });
    OnSaStopping(SystemParamManager::GetInstance().GetParam(STOP_SA_KEY, FALSE_STR) == TRUE_STR);

    IAM_LOGI("success");
    isInit_ = true;
}

void DriverLoadManager::OnTimeout()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("timeout");
    timerId_ = std::nullopt;
    ProcessServiceStatus();
}

void DriverLoadManager::OnDriverManagerAdd()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN(driverStatusListener_ != nullptr);

    auto servMgr = IServiceManager::Get();
    IF_FALSE_LOGE_AND_RETURN(servMgr != nullptr);

    (void)servMgr->UnregisterServiceStatusListener(driverStatusListener_);
    int32_t ret = servMgr->RegisterServiceStatusListener(driverStatusListener_, DEVICE_CLASS_USERAUTH);
    IF_FALSE_LOGE_AND_RETURN(ret == 0);

    auto service = servMgr->GetService(SERVICE_NAME);
    isDriverRunning_ = (service != nullptr);
    IAM_LOGI("service %{public}s running: %{public}d", SERVICE_NAME, isDriverRunning_);

    ProcessServiceStatus();
    IAM_LOGI("end");
}

void DriverLoadManager::OnServiceStart()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("service start");
    isDriverRunning_ = true;
    ProcessServiceStatus();
}

void DriverLoadManager::OnServiceStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("service stop");
    isDriverRunning_ = false;
    ProcessServiceStatus();
}

void DriverLoadManager::OnSaStopping(bool isStopping)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    isSaStopping_ = isStopping;
    ProcessServiceStatus();
}

bool DriverLoadManager::LoadDriver()
{
    auto devMgr = IDeviceManager::Get();
    IF_FALSE_LOGE_AND_RETURN_VAL(devMgr != nullptr, false);

    IAM_LOGI("load hdi service begin");
    int32_t loadDriverRet = devMgr->LoadDevice(SERVICE_NAME);
    if (loadDriverRet != 0) {
        IAM_LOGE("load %{public}s service failed, ret:%{public}d", SERVICE_NAME, loadDriverRet);
        return false;
    }
    return true;
}

bool DriverLoadManager::UnloadDriver()
{
    auto devMgr = IDeviceManager::Get();
    IF_FALSE_LOGE_AND_RETURN_VAL(devMgr != nullptr, false);

    if (devMgr->UnloadDevice(SERVICE_NAME) != 0) {
        IAM_LOGE("unload %{public}s service failed", SERVICE_NAME);
        return false;
    }
    return true;
}

void DriverLoadManager::ProcessServiceStatus()
{
    const uint32_t RETRY_LOAD_INTERVAL = 1000; // 1s

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    bool shouldRunning = !isSaStopping_;
    IAM_LOGI("process service %{public}s status %{public}d, isSaStopping_ %{public}d", SERVICE_NAME, isDriverRunning_,
        isSaStopping_);
    if (isDriverRunning_ != shouldRunning) {
        if (shouldRunning) {
            bool loadDriverRet = LoadDriver();
            if (loadDriverRet) {
                IAM_LOGI("load service %{public}s success", SERVICE_NAME);
                isDriverRunning_ = true;
            }
        } else {
            bool unloadDriverRet = UnloadDriver();
            if (unloadDriverRet) {
                IAM_LOGI("unload service %{public}s success", SERVICE_NAME);
                isDriverRunning_ = false;
            }
        }
    }

    if (isDriverRunning_ == shouldRunning) {
        if (timerId_ != std::nullopt) {
            RelativeTimer::GetInstance().Unregister(timerId_.value());
            timerId_ = std::nullopt;
        }
    } else {
        if (timerId_ == std::nullopt) {
            timerId_ = RelativeTimer::GetInstance().Register([this]() { OnTimeout(); }, RETRY_LOAD_INTERVAL);
            IAM_LOGI("process fail, retry after %{public}d ms", RETRY_LOAD_INTERVAL);
        }
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
