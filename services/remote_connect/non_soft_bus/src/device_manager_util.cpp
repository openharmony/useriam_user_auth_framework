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

#include "device_manager_util.h"

#include "iam_logger.h"
#include <dlfcn.h>
#include <cstdio>

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
DeviceManagerUtil &DeviceManagerUtil::GetInstance()
{
    static DeviceManagerUtil instance;
    return instance;
}

bool DeviceManagerUtil::GetUdidByNetworkId(const std::string &networkId, std::string &udid)
{
    IAM_LOGE("Dynamic load mode: GetUdidByNetworkId not supported");
    return false;
}

bool DeviceManagerUtil::GetNetworkIdByUdid(const std::string &udid, std::string &networkId)
{
    IAM_LOGE("Dynamic load mode: GetNetworkIdByUdid not supported");
    return false;
}

#define RTLD_LAZY 1
using PAclGetDevUdid = int (*)(char *, int);
bool DeviceManagerUtil::GetLocalDeviceUdid(std::string &udid)
{
    static const char *BEGET_PROXY_LIB = "libbeget_proxy.z.so";
    constexpr int UDID_LENGTH = 65;
    char udidDevice[UDID_LENGTH] = {0};
    void *handle = dlopen(BEGET_PROXY_LIB, RTLD_LAZY);
    if (handle == nullptr) {
        IAM_LOGI("load begetlib failed %{public}s", dlerror());
        return false;
    }
    PAclGetDevUdid fun = (PAclGetDevUdid)dlsym(handle, "AclGetDevUdid");
    if (fun == nullptr) {
        IAM_LOGE("get symbol failed %{public}s", dlerror());
        dlclose(handle);
        return false;
    }
    int udidRes = fun(udidDevice, UDID_LENGTH);
    dlclose(handle);
    if (udidRes == 0) {
        IAM_LOGI("GetDeviceUdid udidRes == 0");
        std::string udidString(udidDevice, strlen(udidDevice));
        udid = udidString;
        return true;
    } else {
        IAM_LOGE("GetDeviceUdid get udid failed %{public}d", udidRes);
        return false;
    }
}

bool DeviceManagerUtil::GetLocalDeviceNetWorkId(std::string &networkId)
{
    IAM_LOGE("Dynamic load mode: GetLocalDeviceNetWorkId not supported");
    return false;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS 