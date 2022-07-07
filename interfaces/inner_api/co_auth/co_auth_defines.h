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

#ifndef CO_AUTH_DEFINES_H
#define CO_AUTH_DEFINES_H

#include "parcel.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
/* enums define */
enum AuthAttributeType {
    /* Root tag */
    AUTH_ROOT = 100000,
    /* Result code */
    AUTH_RESULT_CODE = 100001,
    /* Tag of signature data in TLV */
    AUTH_SIGNATURE = 100004,
    /* Identify mode */
    AUTH_IDENTIFY_MODE = 100005,
    /* Tag of templateId data in TLV */
    AUTH_TEMPLATE_ID = 100006,
    /* Tag of templateId list data in TLV */
    AUTH_TEMPLATE_ID_LIST = 100007,
    /* Expected attribute, tag of remain count in TLV */
    AUTH_REMAIN_COUNT = 100009,
    /* Remain time */
    AUTH_REMAIN_TIME = 100010,
    /* Session id, required when decode in C */
    AUTH_SCHEDULE_ID = 100014,
    /* Package name */
    AUTH_CALLER_NAME = 100015,
    /* Schedule version */
    AUTH_SCHEDULE_VERSION = 100016,
    /* Tag of lock out template in TLV */
    AUTH_LOCK_OUT_TEMPLATE = 100018,
    /* Tag of unlock template in TLV */
    AUTH_UNLOCK_TEMPLATE = 100019,
    /* Tag of data */
    AUTH_DATA = 100020,
    /* Tag of auth subType */
    AUTH_SUBTYPE = 100021,
    /* Tag of auth schedule mode */
    AUTH_SCHEDULE_MODE = 100022,
    /* Tag of property */
    AUTH_PROPERTY_MODE = 100023,
    /* Tag of auth type */
    AUTH_TYPE = 100024,
    /* Tag of cred id */
    AUTH_CREDENTIAL_ID = 100025,
    /* Controller */
    AUTH_CONTROLLER = 100026,
    /* calleruid */
    AUTH_CALLER_UID = 100027,
    /* result */
    AUTH_RESULT = 100028,
    /* capability level */
    AUTH_CAPABILITY_LEVEL = 100029,
    /* algorithm setinfo */
    ALGORITHM_INFO
};

enum AuthType : uint32_t {
    ALL = 0,
    PIN = 1,
    FACE = 2,
    FINGERPRINT = 4,
};

/* Safety level of actuator */
enum ExecutorSecureLevel : uint32_t {
    ESL0 = 0,
    ESL1 = 1,
    ESL2 = 2,
    ESL3 = 3,
};

enum ExecutorRole : uint32_t {
    SCHEDULER = 0,
    COLLECTOR = 1,
    VERIFIER = 2,
    ALL_IN_ONE = 3,
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

enum ScheduleMode : uint32_t {
    ENROLL = 0,
    AUTH = 1,
    IDENTIFY = 2,
};


const uint64_t INVALID_EXECUTOR_ID = 0;

struct ExecutorInfo {
    int32_t executorId;
    AuthType authType;
    ExecutorRole role;
    int32_t executorType;
    ExecutorSecureLevel esl;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> deviceId;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
namespace OHOS {
namespace UserIAM {
using AuthAttributeType = OHOS::UserIam::UserAuth::AuthAttributeType;
using AuthType = OHOS::UserIam::UserAuth::AuthType;
using ExecutorSecureLevel = OHOS::UserIam::UserAuth::ExecutorSecureLevel;
using ExecutorRole = OHOS::UserIam::UserAuth::ExecutorRole;
using ResultCode = OHOS::UserIam::UserAuth::ResultCode;
using ExecutorInfo = OHOS::UserIam::UserAuth::ExecutorInfo;
using ScheduleMode = OHOS::UserIam::UserAuth::ScheduleMode;
}
}
#endif // CO_AUTH_DEFINES_H
