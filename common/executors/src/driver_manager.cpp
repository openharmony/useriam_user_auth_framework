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

#include "driver_manager.h"

#include <set>

#include "devsvc_manager_stub.h"
#include "hdf_device_desc.h"
#include "iservice_registry.h"
#include "iservmgr_hdi.h"
#include "parameter.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
const char IAM_EVENT_KEY[] = "bootevent.useriam.fwkready";
int32_t DriverManager::Start(const std::map<std::string, HdiConfig> &hdiName2Config)
{
    IAM_LOGI("start");
    if (!HdiConfigIsValid(hdiName2Config)) {
        IAM_LOGE("service config is not valid");
        return USERAUTH_ERROR;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (started) {
        IAM_LOGE("driver manager already started");
        return USERAUTH_ERROR;
    }
    started = true;
    hdiName2Config_ = hdiName2Config;
    serviceName2Driver_.clear();
    for (auto const &pair : hdiName2Config) {
        auto driver = Common::MakeShared<Driver>(pair.first, pair.second);
        if (driver == nullptr) {
            IAM_LOGE("MakeShared for driver %{public}s failed", pair.first.c_str());
            continue;
        }
        serviceName2Driver_[pair.first] = driver;
        IAM_LOGI("add driver %{public}s", pair.first.c_str());
    }
    SubscribeHdiManagerServiceStatus();
    SubscribeFrameworkReadyEvent();
    IAM_LOGI("success");
    return USERAUTH_SUCCESS;
}

bool DriverManager::HdiConfigIsValid(const std::map<std::string, HdiConfig> &hdiName2Config)
{
    std::set<uint16_t> idSet;
    for (auto const &pair : hdiName2Config) {
        uint16_t id = pair.second.id;
        if (idSet.find(id) != idSet.end()) {
            IAM_LOGE("duplicate hdi id %{public}hu", id);
            return false;
        }
        if (pair.second.driver == nullptr) {
            IAM_LOGE("driver is nullptr");
            return false;
        }
        idSet.insert(id);
    }
    return true;
}

void DriverManager::SubscribeHdiDriverStatus()
{
    IAM_LOGI("start");
    auto servMgr = IServiceManager::Get();
    if (servMgr == nullptr) {
        IAM_LOGE("failed to get IServiceManager");
        return;
    }

    auto listener = new (std::nothrow) HdiServiceStatusListener([](const ServiceStatus &status) {
        auto driver = DriverManager::GetInstance().GetDriverByServiceName(status.serviceName);
        if (driver == nullptr) {
            return;
        }

        IAM_LOGI("service %{public}s receive status %{public}d", status.serviceName.c_str(), status.status);
        switch (status.status) {
            case SERVIE_STATUS_START:
                IAM_LOGI("service %{public}s status change to start", status.serviceName.c_str());
                driver->OnHdiConnect();
                break;
            case SERVIE_STATUS_STOP:
                IAM_LOGI("service %{public}s status change to stop", status.serviceName.c_str());
                driver->OnHdiDisconnect();
                break;
            default:
                IAM_LOGI("service %{public}s status ignored", status.serviceName.c_str());
        }
    });
    IF_FALSE_LOGE_AND_RETURN(listener != nullptr);
    auto listenerPtr = sptr<HdiServiceStatusListener>(listener);
    int32_t ret = servMgr->RegisterServiceStatusListener(listener, DEVICE_CLASS_USERAUTH);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("failed to register service status listener");
        return;
    }
    IAM_LOGI("success");
}

void DriverManager::SubscribeHdiManagerServiceStatus()
{
    IAM_LOGI("start");
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("failed to get SA manager");
        return;
    }
    auto listener = SystemAbilityStatusListener::GetInstance();
    IF_FALSE_LOGE_AND_RETURN(listener != nullptr);
    int32_t ret = sam->SubscribeSystemAbility(DEVICE_SERVICE_MANAGER_SA_ID, listener);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("failed to subscribe status");
        return;
    }
    IAM_LOGI("success");
}

void DriverManager::SubscribeFrameworkReadyEvent()
{
    auto eventCallback = [](const char *key, const char *value, void *context) {
        IAM_LOGI("receive useriam.fwkready event");
        IF_FALSE_LOGE_AND_RETURN(key != nullptr);
        IF_FALSE_LOGE_AND_RETURN(value != nullptr);
        if (strcmp(key, IAM_EVENT_KEY) != 0) {
            IAM_LOGE("event key mismatch");
            return;
        }
        if (strcmp(value, "true")) {
            IAM_LOGE("event value is not true");
            return;
        }
        DriverManager::GetInstance().OnFrameworkReady();
    };
    int32_t ret = WatchParameter(IAM_EVENT_KEY, eventCallback, nullptr);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("WatchParameter fail");
        return;
    }
    IAM_LOGI("success");
}

void DriverManager::OnAllHdiDisconnect()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto const &pair : serviceName2Driver_) {
        if (pair.second == nullptr) {
            IAM_LOGE("pair.second is null");
            continue;
        }
        pair.second->OnHdiDisconnect();
    }
    IAM_LOGI("success");
}

void DriverManager::OnFrameworkReady()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto const &pair : serviceName2Driver_) {
        if (pair.second == nullptr) {
            IAM_LOGE("pair.second is null");
            continue;
        }
        pair.second->OnFrameworkReady();
    }
    IAM_LOGI("success");
}

std::shared_ptr<Driver> DriverManager::GetDriverByServiceName(const std::string &serviceName)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    auto driverIter = serviceName2Driver_.find(serviceName);
    if (driverIter == serviceName2Driver_.end()) {
        return nullptr;
    }
    return driverIter->second;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
