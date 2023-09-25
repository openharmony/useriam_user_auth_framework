/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef IAM_USER_INFO_INTERFACE_H
#define IAM_USER_INFO_INTERFACE_H

#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserInfoInterface {
public:
    virtual ~UserInfoInterface() = default;
    virtual int32_t GetUserId() const = 0;
    virtual PinSubType GetPinSubType() const = 0;
    virtual uint64_t GetSecUserId() const = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_USER_INFO_INTERFACE_H