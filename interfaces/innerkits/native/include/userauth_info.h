/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "parcel.h"

#define SIGN_LEN 32

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
// 认证的类型(口令,人脸)
enum AuthType: uint32_t {
    PIN = 1,
    FACE = 2,
};
// 认证子类型(2D人脸,3D人脸...)
enum AuthSubType: uint64_t {
    /**
     * Authentication sub type six number pin.
     */
    PIN_SIX = 10000,
    /**
     * Authentication sub type self defined number pin.
     */
    PIN_NUMBER = 10001,
    /**
     * Authentication sub type 2D face.
     */
    PIN_MIXED = 10002,
    /**
     * Authentication sub type 2D face.
     */
    FACE_2D = 20000,
    /**
     * Authentication sub type 3D face.
     */
    FACE_3D = 20001
};
// 认证结果可信等级
enum AuthTurstLevel: uint32_t {
    // level 1-4
    ATL1 = 10000,
    ATL2 = 20000,
    ATL3 = 30000,
    ATL4 = 40000
};
// 执行器属性列表
enum GetPropertyType: uint32_t {
    // 认证子类型(此时认证类型已确认)
    AUTH_SUB_TYPE = 1,
    // 剩余认证次数
    REMAIN_TIMES = 2,
    // 冻结时间
    FREEZING_TIME = 3,
};
// 获得属性请求
struct GetPropertyRequest {
    AuthType authType;
    // GetPropertyType
    std::vector<uint32_t> keys;
};
// 执行器属性
struct ExecutorProperty {
    int32_t result;
    AuthSubType authSubType;
    uint32_t remainTimes;
    uint32_t freezingTime;
};
// 执行器属性列表
enum AuthPropertyMode: uint32_t {
        PROPERMODE_DELETE = 0,
        PROPERMODE_GET = 1,
        PROPERMODE_SET = 2,
        PROPERMODE_FREEZE = 3,
        PROPERMODE_UNFREEZE = 4,
};
// 执行器属性列表
enum SetPropertyType: uint32_t {
        INIT_ALGORITHM = 1,
        FREEZE_TEMPLATE = 2,
        THAW_TEMPLATE = 3,
};
struct SetPropertyRequest {
    AuthType authType;
    SetPropertyType key;
    std::vector<uint8_t> setInfo;
};
// 认证结果
struct AuthResult {
    std::vector<uint8_t> token;
    uint32_t remainTimes;
    uint32_t freezingTime;
};
struct CoAuthInfo {
    AuthType authType;
    uint64_t callerID;
    uint64_t contextID;
    std::string pkgName;
    std::vector<uint64_t> sessionIds;
};

struct FreezInfo {
    uint64_t callerID;
    std::string pkgName;
    int32_t resultCode;
    AuthType authType;
};

// 结果码
enum ResultCode: int32_t {
    /**
     * Indicates that authentication is success or ability is supported.
     */
    SUCCESS = 0,
    /**
    * Indicates the authenticator fails to identify user.
    */
    FAIL = 1,
    /**
    * Indicates other errors.
    */
    GENERAL_ERROR = 2,
    /**
    * Indicates that authentication has been canceled.
    */
    CANCELED = 3,
    /**
    * Indicates that authentication has timed out.
    */
    TIMEOUT = 4,
    /**
    * Indicates that this authentication type is not supported.
    */
    TYPE_NOT_SUPPORT = 5,
    /**
    * Indicates that the authentication trust level is not supported.
    */
    TRUST_LEVEL_NOT_SUPPORT = 6,
    /**
    * Indicates that the authentication task is busy. Wait for a few seconds and try again.
    */
    BUSY = 7,
    /**
    * Indicates incorrect parameters.
    */
    INVALID_PARAMETERS = 8,
    /**
    * Indicates that the authenticator is locked.
    */
    LOCKED = 9,
    /**
    * Indicates that the user has not enrolled the authenticator.
    */
    NOT_ENROLLED = 10,
    /**
    * Indicates that IPC communication error.
    */
    IPC_ERROR = 11,
    /**
    * Indicates that invalid contextId.
    */
    INVALID_CONTEXTID = 12,
    /**
    * Indicates that WRITE PARCEL ERROR.
    */
    E_WRITE_PARCEL_ERROR = 13,
    /**
    * Indicates that READ PARCEL ERROR
    */
    E_READ_PARCEL_ERROR = 14,
    /**
    * Indicates that POWER SERVICE FAILED
    */
    E_GET_POWER_SERVICE_FAILED = 15,
    /**
    * Indicates that executor schudle undone
    */
    E_RET_UNDONE = 16,
    /**
    * Indicates that executor schudle undone
    */
    E_RET_NOSERVER = 17,
    /**
    * ERRORCODE_MAX.
    */
    ERRORCODE_MAX = 18
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USERAUTH_INFO_H
