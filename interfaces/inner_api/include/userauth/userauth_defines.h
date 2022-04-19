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

#ifndef USERAUTH_DEFINES_H
#define USERAUTH_DEFINES_H

#include <map>
#include "parcel.h"
#include "common_info.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
enum AuthType : uint32_t {
    PIN = 1,
    FACE = 2,
};

enum class UserAuthType {
    FACE = 2,
    FINGERPRINT = 4,
};

enum AuthSubType : uint64_t {
    PIN_SIX = 10000,
    PIN_NUMBER = 10001,
    PIN_MIXED = 10002,
    FACE_2D = 20000,
    FACE_3D = 20001
};

enum AuthTrustLevel : uint32_t {
    ATL1 = 10000,
    ATL2 = 20000,
    ATL3 = 30000,
    ATL4 = 40000
};

enum GetPropertyType : uint32_t {
    AUTH_SUB_TYPE = 1,
    REMAIN_TIMES = 2,
    FREEZING_TIME = 3,
};

struct GetPropertyRequest {
    AuthType authType {0};
    std::vector<uint32_t> keys {};
};

struct ExecutorProperty {
    int32_t result;
    AuthSubType authSubType;
    uint32_t remainTimes;
    uint32_t freezingTime;
};

enum AuthPropertyMode : uint32_t {
    PROPERMODE_DELETE = 0,
    PROPERMODE_GET = 1,
    PROPERMODE_SET = 2,
    PROPERMODE_FREEZE = 3,
    PROPERMODE_UNFREEZE = 4,
    PROPERMODE_INIT_ALGORITHM = 5,
    PROPERMODE_RELEASE_ALGORITHM = 6,
    PROPERMODE_SET_SURFACE_ID = 100,
};

enum SetPropertyType : uint32_t {
    INIT_ALGORITHM = 1,
    FREEZE_TEMPLATE = 2,
    THAW_TEMPLATE = 3,
};

struct SetPropertyRequest {
    AuthType authType {0};
    SetPropertyType key {0};
    std::vector<uint8_t> setInfo {};
};

struct AuthResult {
    std::vector<uint8_t> token {};
    uint32_t remainTimes {0};
    uint32_t freezingTime {0};
};

struct FreezeInfo {
    uint64_t callerID;
    std::string pkgName;
    int32_t resultCode;
    AuthType authType;
};

struct CallerInfo {
    uint64_t callerUID;
    int32_t userID {0};
    std::string pkgName;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // USERAUTH_DEFINES_H
