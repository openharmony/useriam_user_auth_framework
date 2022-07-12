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

#ifndef USER_IDM_CLIENT_DEFINES_H
#define USER_IDM_CLIENT_DEFINES_H

#include <optional>

#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct CredentialInfo {
    AuthType authType {0};
    std::optional<PinSubType> pinType {};
    uint64_t credentialId {0};
    uint64_t templateId {0};
};

struct EnrolledInfo {
    AuthType authType {0};
    uint64_t enrolledId {0};
};

struct SecUserInfo {
    uint64_t secureUid {0};
    std::vector<EnrolledInfo> enrolledInfo {};
};

struct CredentialParameters {
    AuthType authType {0};
    std::optional<PinSubType> pinType {};
    std::vector<uint8_t> token {};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_IDM_CLIENT_DEFINES_H