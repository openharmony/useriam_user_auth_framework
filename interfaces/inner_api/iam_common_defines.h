/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

/**
 * @file iam_common_defines.h
 *
 * @brief Some common defines in IAM.
 * @since 3.1
 * @version 3.2
 */

#ifndef IAM_COMMON_DEFINES_H
#define IAM_COMMON_DEFINES_H

#include <cstddef>
#include <cstdint>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
/** Max length of challenge. */
constexpr size_t MAX_CHALLENG_LEN = 32;
constexpr int32_t USER_AUTH_TIP_SINGLE_AUTH_RESULT = 9999;
constexpr int INVALID_SOCKET_ID = -1;
constexpr int32_t MAIN_USER_ID = 100;
/**
 * @brief Defines authentication type.
 */
enum AuthType : int32_t {
    /** All authentication types. */
    ALL = 0,
    /** Pin authentication. */
    PIN = 1,
    /** Face authentication. */
    FACE = 2,
    /** Fingerprint authentication. */
    FINGERPRINT = 4,
    /** recovery key authentication. */
    RECOVERY_KEY = 8,
};

/**
 * @brief Defines pin auth's subtype.
 */
enum PinSubType : int32_t {
    /** Digit password with fixed length of six. */
    PIN_SIX = 10000,
    /** Digit password with unfixed length. */
    PIN_NUMBER = 10001,
    /** Complex password with number and alphabet. */
    PIN_MIXED = 10002,
    /** Max pin. */
    PIN_MAX,
};

/**
 * @brief Enumerates executor roles.
 */
enum ExecutorRole : int32_t {
    /** Scheduler executor. */
    SCHEDULER = 0,
    /** The executor acts as a collector. */
    COLLECTOR = 1,
    /** The executor acts as a verifier. */
    VERIFIER = 2,
    /** The executor acts as a collector and verifier. */
    ALL_IN_ONE = 3,
};

/**
 * @brief Enumerates executor security levels.
 */
enum ExecutorSecureLevel : int32_t {
    /** Executor secure level 0. */
    ESL0 = 0,
    /** Executor secure level 1. */
    ESL1 = 1,
    /** Executor secure level 2. */
    ESL2 = 2,
    /** Executor secure level 3. */
    ESL3 = 3,
};

/**
 * @brief Authentication trust level
 */
enum AuthTrustLevel : uint32_t {
    /** Auth trust level 1. */
    ATL1 = 10000,
    /** Auth trust level 2. */
    ATL2 = 20000,
    /** Auth trust level 3. */
    ATL3 = 30000,
    /** Auth trust level 4. */
    ATL4 = 40000,
};

/**
 * @brief Schedule mode.
 */
enum ScheduleMode : int32_t {
    /** The schedule mode is enrollment. */
    ENROLL = 0,
    /** The schedule mode is authentication. */
    AUTH = 1,
    /** The schedule mode is identification. */
    IDENTIFY = 2,
};

/**
 * @brief Property mode.
 */
enum PropertyMode : uint32_t {
    /** The property mode is init algorithm. */
    PROPERTY_INIT_ALGORITHM = 1,
    /** The property mode is delete. */
    PROPERTY_MODE_DEL = 2,
    /** The property mode is get. */
    PROPERTY_MODE_GET = 3,
    /** The property mode is set. */
    PROPERTY_MODE_SET = 4,
    /** The property mode is freeze. */
    PROPERTY_MODE_FREEZE = 5,
    /** The property mode is unfreeze. */
    PROPERTY_MODE_UNFREEZE = 6,
    /** The property mode is set cached templates. */
    PROPERTY_MODE_SET_CACHED_TEMPLATES = 7,
    /** The property mode is notify collector ready. */
    PROPERTY_MODE_NOTIFY_COLLECTOR_READY = 8,
};

/**
 * @brief The result code.
 */
enum ResultCode : int32_t {
    /** The result is success. */
    SUCCESS = 0,
    /** Compile fail. */
    FAIL = 1,
    /** The result is fail, because an unknown error occurred. */
    GENERAL_ERROR = 2,
    /** The result is fail, because the request was canceled. */
    CANCELED = 3,
    /** The result is fail ,because of time out. */
    TIMEOUT = 4,
    /** The result is fail ,because type is not support. */
    TYPE_NOT_SUPPORT = 5,
    /** The result is fail ,because trust level is not support. */
    TRUST_LEVEL_NOT_SUPPORT = 6,
    /** The result is fail, because the service was busy. */
    BUSY = 7,
    /** The result is fail, because parameters is invalid. */
    INVALID_PARAMETERS = 8,
    /** The result if fail, because the status is locked. */
    LOCKED = 9,
    /** The result is fail, because the user was not enrolled. */
    NOT_ENROLLED = 10,
    /** The result is fail, because canceled from widget. */
    CANCELED_FROM_WIDGET = 11,
    /** The result is fail, because the hardware is not supported. */
    HARDWARE_NOT_SUPPORTED = 12,
    /** The result is fail, because the pin credential is expired. */
    PIN_EXPIRED = 13,
    /** The result is fail, because the PIN_MIXED does not pass complexity check. */
    COMPLEXITY_CHECK_FAILED = 14,
    /** The result is fail, because something wrong from system. */
    SYSTEM_ERROR_CODE_BEGIN = 1000,
    /** The result is fail, because something wrong from ipc. */
    IPC_ERROR = 1001,
    /** The result is fail, because the context ID is invalid. */
    INVALID_CONTEXT_ID = 1002,
    /** The result is fail, because something wrong when read parcel. */
    READ_PARCEL_ERROR = 1003,
    /** The result is fail, because something wrong when write parcel. */
    WRITE_PARCEL_ERROR = 1004,
    /** The result is fail, because permission check is failed. */
    CHECK_PERMISSION_FAILED = 1005,
    /** The result is fail, because the hdi interface is invalid. */
    INVALID_HDI_INTERFACE = 1006,
    /** The result is fail, because the caller app is not system. */
    CHECK_SYSTEM_APP_FAILED = 1007,
    /** The result is fail, because something wrong when create socket. */
    CREATE_SOCKET_FAILED = 1008,
    /** The result is fail, because something wrong when listen socket. */
    LISTEN_SOCKET_FAILED = 1009,
    /** The result is fail, because something wrong when bind socket. */
    BIND_SOCKET_FAILED = 1010,
    /** The result is fail, because something wrong from vendor. */
    VENDOR_ERROR_CODE_BEGIN = 10000,
};

/**
 * @brief The auth intent.
 */
enum AuthIntent : int {
    /**< The auth intent is default. */
    DEFAULT = 0,
    /**< The auth intent is unlock. */
    UNLOCK = 1,
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_COMMON_DEFINES_H
