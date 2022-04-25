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

#ifndef USERIDM_INFO_H
#define USERIDM_INFO_H

#include <vector>
#include <cstdint>

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
enum CoAuthType {
    ADD_PIN_CRED = 0,
    MODIFY_CRED,
    ADD_FACE_CRED,
};

enum AuthType {
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

enum AuthSubType {
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

enum IDMResultCode {
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
    CHECK_PERMISSION_FAILED = 11,
};

struct CredentialInfo {
    uint64_t credentialId;
    AuthType authType;
    AuthSubType authSubType;
    uint64_t templateId;
};

struct EnrolledCredInfo {
    uint64_t credentialId;
    AuthType authType;
    AuthSubType authSubType;
    uint64_t templateId;
};

struct EnrolledInfo {
    AuthType authType;
    uint64_t enrolledId;
};

struct SecInfo {
    uint64_t secureUid;
    uint32_t enrolledInfoLen;
    std::vector<EnrolledInfo> enrolledInfo;
};

struct AddCredInfo {
    AuthType authType;
    AuthSubType authSubType;
    std::vector<uint8_t> token;
};

struct  RequestResult {
    uint64_t credentialId;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS

#endif // USERIDM_INFO_H
