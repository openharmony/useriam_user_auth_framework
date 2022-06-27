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

#ifndef IAM_RESULT_CODE_H
#define IAM_RESULT_CODE_H

#include <cstdint>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
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
#endif // IAM_RESULT_CODE_H