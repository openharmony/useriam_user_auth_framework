/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICE_MANAGER_H
#define OHOS_DEVICE_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>

#include "securec.h"
#include "device_manager_callback.h"
#include "dm_device_info.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceManager {
public:
    static DeviceManager &GetInstance();
    virtual ~DeviceManager();

    virtual int32_t InitDeviceManager(const std::string &pkgName,
        std::shared_ptr<DmInitCallback> dmInitCallback) = 0;
    virtual int32_t UnInitDeviceManager(const std::string &pkgName) = 0;
    virtual int32_t GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
        std::vector<DmDeviceInfo> &deviceList) = 0;
    virtual int32_t GetUdidByNetworkId(const std::string &pkgName, const std::string &netWorkId,
        std::string &udid) = 0;
    virtual int32_t GetLocalDeviceNetWorkId(const std::string &pkgName, std::string &networkId) = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DEVICE_MANAGER_H
