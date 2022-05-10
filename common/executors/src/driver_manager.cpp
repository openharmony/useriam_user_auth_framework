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
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iservice_registry.h"
#include "iservmgr_hdi.h"
#include "parameter.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
const std::string GROUP_SCHEDULE = "GROUP_SCHEDULE";
const char IAM_EVENT_KEY[] = "bootevent.useriam.fwkready";
int32_t DriverManager::Start(const std::map<std::string, HdiConfig> &hdiName2Config)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!HdiConfigIsValid(hdiName2Config)) {
        IAM_LOGE("service config is not valid");
        return USERAUTH_ERROR;
    }
    hdiName2Config_ = hdiName2Config;
    serviceName2Driver_.clear();
    for (auto const &pair : hdiName2Config) {
        auto driver = Common::MakeShared<Driver>(pair.first, pair.second);
        if (driver == nullptr) {
            IAM_LOGE("make_shared for driver %{public}s failed", pair.first.c_str());
            continue;
        }
        serviceName2Driver_[pair.first] = driver;
        IAM_LOGI("add driver %{public}s", pair.first.c_str());
    }
    SubscribeHdiManagerServiceStatus();
    SubscribeHdiDriverStatus();
    SubscribeFrameworkRedayEvent();
    OnAllHdiConnect();
    IAM_LOGI("success");
    return USERAUTH_SUCCESS;
}

bool DriverManager::HdiConfigIsValid(const std::map<std::string, HdiConfig> &hdiName2Config)
{
    std::set<uint16_t> idSet;
    for (auto const &pair : hdiName2Config) {
        uint16_t id = pair.second.id;
        if (idSet.count(id) != 0) {
            IAM_LOGE("duplicate hdi id %{public}d", id);
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

    int32_t ret = servMgr->RegisterServiceStatusListener(this, DEVICE_CLASS_USERAUTH);
    if (ret != USERAUTH_SUCCESS) {
        IAM_LOGE("failed to register service status listener");
        return;
    }
    IAM_LOGI("success");
}

bool DriverManager::HdiDriverIsRunning(const std::string &serviceName)
{
    auto servMgr = IServiceManager::Get();
    if (servMgr == nullptr) {
        IAM_LOGE("failed to get IServiceManager");
        return false;
    }

    auto service = servMgr->GetService(serviceName.c_str());
    if (service == nullptr) {
        IAM_LOGE("hdi driver is not running");
        return false;
    }

    IAM_LOGI("hdi driver is running");
    return true;
}

void DriverManager::OnReceive(const ServiceStatus &status)
{
    IAM_LOGI("service %{public}s receive status", status.serviceName.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (serviceName2Driver_.count(status.serviceName) == 0) {
        IAM_LOGI("service name not match");
        return;
    }

    switch (status.status) {
        case SERVIE_STATUS_START:
            IAM_LOGI("service %{public}s status change to start", status.serviceName.c_str());
            if (!HdiDriverIsRunning(status.serviceName)) {
                IAM_LOGE("service %{public}s is not running, ignore this message", status.serviceName.c_str());
                break;
            }
            serviceName2Driver_[status.serviceName]->OnHdiConnect();
            break;
        case SERVIE_STATUS_STOP:
            IAM_LOGI("service %{public}s status change to stop", status.serviceName.c_str());
            if (HdiDriverIsRunning(status.serviceName)) {
                IAM_LOGE("service %{public}s is running, ignore this message", status.serviceName.c_str());
                break;
            }
            serviceName2Driver_[status.serviceName]->OnHdiDisconnect();
            break;
        default:
            IAM_LOGE("service %{public}s status invalid", status.serviceName.c_str());
    }
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

void DriverManager::SubscribeFrameworkRedayEvent()
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
            IAM_LOGI("event value is not true");
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
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto const &pair : serviceName2Driver_) {
        pair.second->OnHdiDisconnect();
    }
    IAM_LOGI("success");
}

void DriverManager::OnAllHdiConnect()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto const &pair : serviceName2Driver_) {
        pair.second->OnHdiConnect();
    }
    IAM_LOGI("success");
}

void DriverManager::OnFrameworkReady()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto const &pair : serviceName2Driver_) {
        pair.second->OnFrameworkReady();
    }
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
