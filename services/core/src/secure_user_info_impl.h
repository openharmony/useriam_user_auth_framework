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

#ifndef IAM_SECURE_USER_INFO_IMPL_H
#define IAM_SECURE_USER_INFO_IMPL_H

#include "nocopyable.h"

#include "secure_user_info_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SecureUserInfoImpl final : public SecureUserInfoInterface, public NoCopyable {
public:
    SecureUserInfoImpl(int32_t userId, uint64_t secUserId,
        std::vector<std::shared_ptr<EnrolledInfoInterface>> &enrolledInfos);
    ~SecureUserInfoImpl() override = default;
    int32_t GetUserId() const override;
    uint64_t GetSecUserId() const override;
    std::vector<std::shared_ptr<EnrolledInfoInterface>> GetEnrolledInfo() const override;

private:
    int32_t userId_ {0};
    uint64_t secUserId_ {0};
    std::vector<std::shared_ptr<EnrolledInfoInterface>> enrolledInfos_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SECURE_USER_INFO_IMPL_H