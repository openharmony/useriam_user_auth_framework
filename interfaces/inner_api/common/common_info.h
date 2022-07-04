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
namespace UserIam {
namespace UserAuth {
enum AuthType : uint32_t {
    /**
     * Authentication type all.
     */
    ALL = 0,
    /**
     * Authentication type pin.
     */
    PIN = 1,
    /**
     * Authentication type face.
     */
    FACE = 2,
};

enum AuthSubType : uint64_t {
    /**
     * Authentication sub type six number pin.
     */
    PIN_SIX = 10000,
    /**
     * Authentication sub type self defined number pin.
     */
    PIN_NUMBER = 10001,
    /**
     * Authentication sub type mixed pin.
     */
    PIN_MIXED = 10002,
    /**
     * Authentication sub type 2D face.
     */
    FACE_2D = 20000,
    /**
     * Authentication sub type 3D face.
     */
    FACE_3D = 20001,
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
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using AuthType = OHOS::UserIam::UserAuth::AuthType;
using AuthSubType = OHOS::UserIam::UserAuth::AuthSubType;
using ResultCode = OHOS::UserIam::UserAuth::ResultCode;
}
}
}
namespace OHOS {
namespace UserIAM {
namespace UserIDM {
using AuthType = OHOS::UserIam::UserAuth::AuthType;
using AuthSubType = OHOS::UserIam::UserAuth::AuthSubType;
using ResultCode = OHOS::UserIam::UserAuth::ResultCode;
}
}
}
#endif // COMMON_INFO_H
