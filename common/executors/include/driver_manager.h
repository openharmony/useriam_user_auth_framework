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

#ifndef DRIVER_MANAGER_H
#define DRIVER_MANAGER_H

#include <cstdint>
#include <map>

#include "iservstat_listener_hdi.h"
#include "singleton.h"

#include "driver.h"
#include "iauth_driver_hdi.h"
#include "idriver_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace HDI::ServiceManager::V1_0;

class DriverManager : public Singleton<DriverManager> {
public:
    DriverManager();
    ~DriverManager() override = default;
    int32_t Start(const std::map<std::string, HdiConfig> &hdiName2Config);
    void OnFrameworkReady();
    void OnAllHdiDisconnect();
    void SubscribeHdiDriverStatus();
    std::shared_ptr<Driver> GetDriverByServiceName(const std::string &serviceName);

private:
    class HdiServiceStatusListener;
    bool HdiConfigIsValid(const std::map<std::string, HdiConfig> &hdiName2Config);
    void SubscribeServiceStatus();
    void SubscribeFrameworkReadyEvent();

    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Driver>> serviceName2Driver_;
};

class DriverManager ::HdiServiceStatusListener : public ServStatListenerStub {
public:
    using StatusCallback = std::function<void(const ServiceStatus &)>;
    explicit HdiServiceStatusListener(StatusCallback callback) : callback_(std::move(callback))
    {
    }
    ~HdiServiceStatusListener() override = default;
    void OnReceive(const ServiceStatus &status) override
    {
        callback_(status);
    }

private:
    StatusCallback callback_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // DRIVER_MANAGER_H