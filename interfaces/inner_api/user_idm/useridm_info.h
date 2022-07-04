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
#include "common_info.h"
#include "user_idm_callback.h"
#include "user_idm_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum CoAuthType {
    ADD_PIN_CRED = 0,
    MODIFY_CRED,
    ADD_FACE_CRED,
};

enum IDMResultCode {
    CHECK_PERMISSION_FAILED = 11,
};

struct EnrolledCredInfo {
    uint64_t credentialId;
    AuthType authType;
    AuthSubType authSubType;
    uint64_t templateId;
};

}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
namespace OHOS {
namespace UserIAM {
namespace UserIDM {
using CoAuthType = OHOS::UserIam::UserAuth::CoAuthType;
using IDMResultCode = OHOS::UserIam::UserAuth::IDMResultCode;
using EnrolledCredInfo = OHOS::UserIam::UserAuth::EnrolledCredInfo;
}
}
}
#endif // USERIDM_INFO_H
