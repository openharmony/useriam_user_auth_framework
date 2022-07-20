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

#ifndef IAM_ENROLLED_INFO_IMPL_H
#define IAM_ENROLLED_INFO_IMPL_H

#include <cstdint>
#include <memory>

#include "enrolled_info.h"
#include "hdi_wrapper.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EnrolledInfoImpl final : public EnrolledInfo, public NoCopyable {
public:
    using HdiEnrolledInfo = OHOS::HDI::UserAuth::V1_0::EnrolledInfo;
    EnrolledInfoImpl(int32_t userId, const HdiEnrolledInfo &info);
    ~EnrolledInfoImpl() override = default;
    AuthType GetAuthType() const override;
    int32_t GetUserId() const override;
    uint64_t GetEnrolledId() const override;

private:
    int32_t userId_;
    HdiEnrolledInfo info_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_ENROLLED_INFO_IMPL_H