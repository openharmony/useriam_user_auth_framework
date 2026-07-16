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

#ifndef OHOS_DM_DEVICE_INFO_H
#define OHOS_DM_DEVICE_INFO_H

#include <cstdint>
#include <string>

#define DM_MAX_DEVICE_ID_LEN (97)
#define DM_MAX_DEVICE_NAME_LEN (129)

namespace OHOS {
namespace DistributedHardware {
typedef enum DmDeviceType {
    DEVICE_TYPE_UNKNOWN = 0x00,
    DEVICE_TYPE_WIFI_CAMERA = 0x08,
    DEVICE_TYPE_AUDIO = 0x0A,
    DEVICE_TYPE_PC = 0x0C,
    DEVICE_TYPE_PHONE = 0x0E,
    DEVICE_TYPE_PAD = 0x11,
    DEVICE_TYPE_WATCH = 0x6D,
    DEVICE_TYPE_CAR = 0x83,
    DEVICE_TYPE_TV = 0x9C,
} DmDeviceType;

typedef enum DmAuthForm {
    INVALID_TYPE = -1,
    PEER_TO_PEER = 0,
    IDENTICAL_ACCOUNT = 1,
    ACROSS_ACCOUNT = 2,
} DmAuthForm;

typedef struct DmDeviceInfo {
    char deviceId[DM_MAX_DEVICE_ID_LEN] = {0};
    char deviceName[DM_MAX_DEVICE_NAME_LEN] = {0};
    uint16_t deviceTypeId = DmDeviceType::DEVICE_TYPE_UNKNOWN;
    char networkId[DM_MAX_DEVICE_ID_LEN] = {0};
    int32_t range = 0;
    int32_t networkType = 0;
    DmAuthForm authForm = DmAuthForm::INVALID_TYPE;
    std::string extraData = "";
} DmDeviceInfo;
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_DEVICE_INFO_H
