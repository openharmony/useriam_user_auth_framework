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

#include "sec_user_info_impl.h"

#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
SecUserInfoImpl::SecUserInfoImpl(uint64_t secUserId, std::vector<std::shared_ptr<SecEnrolledInfo>> info)
    : secUserId_(secUserId), info_(std::move(info))
{
}

int32_t SecUserInfoImpl::GetUserId() const
{
    return 0;
}

PinSubType SecUserInfoImpl::GetPinSubType() const
{
    return PIN_SIX;
}

uint64_t SecUserInfoImpl::GetSecUserId() const
{
    return secUserId_;
}

std::vector<std::shared_ptr<SecEnrolledInfo>> SecUserInfoImpl::GetEnrolledInfo() const
{
    return info_;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS