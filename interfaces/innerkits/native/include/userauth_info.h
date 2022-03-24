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

#ifndef USERAUTH_INFO_H
#define USERAUTH_INFO_H

#include <map>
#include "parcel.h"

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

struct CoAuthInfo {
    AuthType authType {0};
    uint64_t callerID {0};
    uint64_t contextID {0};
    int32_t userID {0};
    std::string pkgName;
    std::vector<uint64_t> sessionIds;
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

enum ResultCode : int32_t {
    SUCCESS = 0,
    FAIL = 1,
    GENERAL_ERROR = 2,
    CANCELED = 3,
    TIMEOUT = 4,
    TYPE_NOT_SUPPORT = 5,
    TRUST_LEVEL_NOT_SUPPORT = 6,
    BUSY = 7,
    INVALID_PARAMETERS = 8,
    LOCKED = 9,
    NOT_ENROLLED = 10,
    IPC_ERROR = 11,
    INVALID_CONTEXT_ID = 12,
    E_WRITE_PARCEL_ERROR = 13,
    E_READ_PARCEL_ERROR = 14,
    E_GET_POWER_SERVICE_FAILED = 15,
    E_RET_UNDONE = 16,
    E_RET_NOSERVER = 17,
    E_CHECK_PERMISSION_FAILED = 18,
    ERRORCODE_MAX = 19
};

// For API6
enum class AuthenticationResult {
    NO_SUPPORT = -1,
    SUCCESS = 0,
    COMPARE_FAILURE = 1,
    CANCELED = 2,
    TIMEOUT = 3,
    CAMERA_FAIL = 4,
    BUSY = 5,
    INVALID_PARAMETERS = 6,
    LOCKED = 7,
    NOT_ENROLLED = 8,
    GENERAL_ERROR = 100,
};

const std::map<int32_t, AuthenticationResult> result2ExecuteResult = {
    {ResultCode::SUCCESS, AuthenticationResult::SUCCESS},
    {ResultCode::FAIL, AuthenticationResult::COMPARE_FAILURE},
    {ResultCode::GENERAL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::CANCELED, AuthenticationResult::CANCELED},
    {ResultCode::TIMEOUT, AuthenticationResult::TIMEOUT},
    {ResultCode::TYPE_NOT_SUPPORT, AuthenticationResult::NO_SUPPORT},
    {ResultCode::TRUST_LEVEL_NOT_SUPPORT, AuthenticationResult::NO_SUPPORT},
    {ResultCode::BUSY, AuthenticationResult::BUSY},
    {ResultCode::INVALID_PARAMETERS, AuthenticationResult::INVALID_PARAMETERS},
    {ResultCode::LOCKED, AuthenticationResult::LOCKED},
    {ResultCode::NOT_ENROLLED, AuthenticationResult::NOT_ENROLLED},
    {ResultCode::IPC_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::INVALID_CONTEXT_ID, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::E_WRITE_PARCEL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::E_READ_PARCEL_ERROR, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::E_GET_POWER_SERVICE_FAILED, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::E_RET_UNDONE, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::E_RET_NOSERVER, AuthenticationResult::GENERAL_ERROR},
    {ResultCode::E_CHECK_PERMISSION_FAILED, AuthenticationResult::GENERAL_ERROR},
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // USERAUTH_INFO_H
