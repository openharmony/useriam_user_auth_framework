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

#ifndef IAM_USER_INFO_IMPL_H
#define IAM_USER_INFO_IMPL_H

#include "nocopyable.h"

#include "user_info_interface.h"
#include "hdi_wrapper.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserInfoImpl final : public UserInfoInterface, public NoCopyable {
public:
    UserInfoImpl(const int32_t userId, const UserInfo &userInfo);
    ~UserInfoImpl() override = default;
    int32_t GetUserId() const override;
    uint64_t GetSecUserId() const override;
    PinSubType GetPinSubType() const override;

private:
    int32_t userId_ {0};
    UserInfo userInfo_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_USER_INFO_IMPL_H