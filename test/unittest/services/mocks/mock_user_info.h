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
#ifndef IAM_MOCK_USER_INFO_H
#define IAM_MOCK_USER_INFO_H

#include <gmock/gmock.h>

#include "user_info_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserInfo final : public UserInfoInterface {
public:
    ~MockSecureUserInfo() override = default;
    MOCK_CONST_METHOD0(GetUserId, int32_t());
    MOCK_CONST_METHOD0(GetSecUserId, uint64_t());
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_INFO_H