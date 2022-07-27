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

#include "secure_user_info_impl.h"
#include "enrolled_info_impl.h"

#include "hdi_wrapper.h"
#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
SecureUserInfoImpl::SecureUserInfoImpl(int32_t userId, PinSubType pinSubType, uint64_t secUserId,
    std::vector<std::shared_ptr<EnrolledInfo>> info)
    : userId_(userId),
      pinSubType_(pinSubType),
      secUserId_(secUserId),
      info_(std::move(info))
{
}

SecureUserInfoImpl::~SecureUserInfoImpl() = default;

int32_t SecureUserInfoImpl::GetUserId() const
{
    return userId_;
}

PinSubType SecureUserInfoImpl::GetPinSubType() const
{
    return pinSubType_;
}

uint64_t SecureUserInfoImpl::GetSecUserId() const
{
    return secUserId_;
}

std::vector<std::shared_ptr<EnrolledInfo>> SecureUserInfoImpl::GetEnrolledInfo() const
{
    return info_;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS