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

#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
inline const char *AuthTypeToStr(AuthType authType)
{
    switch (authType) {
        case ALL:
            return "All";
        case PIN:
            return "Pin";
        case FACE:
            return "Face";
        case FINGERPRINT:
            return "Fingerprint";
        default:
            return "";
    }
}

enum SetPropertyType : uint32_t {
    INIT_ALGORITHM = 1,
    FREEZE_TEMPLATE = 2,
    THAW_TEMPLATE = 3,
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_TYPES_H