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

#ifndef COMMON_INFO_H
#define COMMON_INFO_H

#include <map>
#include "parcel.h"

namespace OHOS {
namespace UserIAM {
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
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // COMMON_INFO_H
