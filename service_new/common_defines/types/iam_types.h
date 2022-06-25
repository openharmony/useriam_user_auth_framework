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

#ifndef IAM_TYPES_H
#define IAM_TYPES_H

#include <vector>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum AuthType : uint32_t {
    ALL = 0,
    PIN = 1,
    FACE = 2,
    FINGERPRINT = 4,
};

enum PinSubType : uint64_t {
    PIN_SIX = 10000,
    PIN_NUMBER = 10001,
    PIN_MIXED = 10002,
    PIN_MAX,
};

enum ExecutorRole : uint32_t {
    SCHEDULER = 0, // not visible externally
    COLLECTOR = 1,
    VERIFIER = 2,
    ALL_IN_ONE = 3,
};

enum ExecutorSecureLevel : uint32_t {
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

enum ScheduleMode : uint32_t {
    ENROLL = 0,
    AUTH = 1,
    IDENTIFY = 2,
};

enum PropertyMode : uint32_t {
    PROPERTY_MODE_DEL = 0,
    PROPERTY_MODE_GET = 1,
    PROPERTY_MODE_SET = 2,
    PROPERTY_MODE_FREEZE = 3,
    PROPERTY_MODE_UNFREEZE = 4,
    PROPERTY_MODE_INIT_ALGORITHM = 5,
    PROPERTY_MODE_RELEASE_ALGORITHM = 6,
    PROPERTY_MODE_SET_SURFACE_ID = 100,
};

enum SetPropertyType : uint32_t {
    INIT_ALGORITHM = 1,
    FREEZE_TEMPLATE = 2,
    THAW_TEMPLATE = 3,
};

// struct defines
struct ExecutorRegisterInfo {
    AuthType authType;
    ExecutorRole executorRole;
    uint32_t executorSensorHint; // for multiple sensors index
    uint32_t executorMatcher;    // for executors matcher
    ExecutorSecureLevel esl;
    std::vector<uint8_t> publicKey;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_TYPES_H