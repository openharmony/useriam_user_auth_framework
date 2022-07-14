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

#ifndef SEC_USER_INFO_IMPL_H
#define SEC_USER_INFO_IMPL_H

#include "user_idm_callback_interface.h"

#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using SecEnrolledInfo = IdmGetSecureUserInfoCallbackInterface::EnrolledInfo;
class SecUserInfoImpl final : public IdmGetSecureUserInfoCallbackInterface::SecureUserInfo, public NoCopyable {
public:
    SecUserInfoImpl(uint64_t secUserId, std::vector<std::shared_ptr<SecEnrolledInfo>> info);
    ~SecUserInfoImpl() override = default;
    int32_t GetUserId() const override;
    PinSubType GetPinSubType() const override;
    uint64_t GetSecUserId() const override;
    std::vector<std::shared_ptr<SecEnrolledInfo>> GetEnrolledInfo() const override;

private:
    uint64_t secUserId_ {0};
    std::vector<std::shared_ptr<SecEnrolledInfo>> info_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // SEC_USER_INFO_IMPL_H