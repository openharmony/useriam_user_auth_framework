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

#ifndef IAM_COMMON_DEFINES_H
#define IAM_COMMON_DEFINES_H

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr size_t MAX_CHALLENG_LEN = 32;

enum AuthType : int32_t {
    ALL = 0,
    PIN = 1,
    FACE = 2,
    FINGERPRINT = 4,
};

enum PinSubType : int32_t {
    PIN_SIX = 10000,
    PIN_NUMBER = 10001,
    PIN_MIXED = 10002,
    PIN_MAX,
};

enum ExecutorRole : int32_t {
    SCHEDULER = 0,
    COLLECTOR = 1,
    VERIFIER = 2,
    ALL_IN_ONE = 3,
};

enum ExecutorSecureLevel : int32_t {
    ESL0 = 0,
    ESL1 = 1,
    ESL2 = 2,
    ESL3 = 3,
};

enum AuthTrustLevel : uint32_t {
    ATL1 = 10000,
    ATL2 = 20000,
    ATL3 = 30000,
    ATL4 = 40000,
};

enum ScheduleMode : int32_t {
    ENROLL = 0,
    AUTH = 1,
    IDENTIFY = 2,
};

enum PropertyMode : uint32_t {
    PROPERTY_INIT_ALGORITHM = 1,
    PROPERTY_MODE_DEL = 2,
    PROPERTY_MODE_GET = 3,
    PROPERTY_MODE_SET = 4,
    PROPERTY_MODE_FREEZE = 5,
    PROPERTY_MODE_UNFREEZE = 6,
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
    HARDWARE_NOT_SUPPORTED = 11,
    SYSTEM_ERROR_CODE_BEGIN = 1000, // error code for system
    IPC_ERROR = 1001,
    INVALID_CONTEXT_ID = 1002,
    READ_PARCEL_ERROR = 1003,
    WRITE_PARCEL_ERROR = 1004,
    CHECK_PERMISSION_FAILED = 1005,
    INVALID_HDI_INTERFACE = 1006,
    VENDOR_ERROR_CODE_BEGIN = 10000, // error code for vendor
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_COMMON_DEFINES_H
