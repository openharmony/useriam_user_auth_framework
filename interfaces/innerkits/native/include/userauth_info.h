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
#include "common_info.h"
#include "userauth_defines.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
struct CoAuthInfo {
    AuthType authType {0};
    uint64_t callerID {0};
    uint64_t contextID {0};
    int32_t userID {0};
    std::string pkgName;
    std::vector<uint64_t> sessionIds;
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
