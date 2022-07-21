/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "enrolled_info_test.h"
#include "enrolled_info_impl.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V1_0::EnrolledInfo;
using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;

void EnrolledInfoTest::SetUpTestCase()
{
}

void EnrolledInfoTest::TearDownTestCase()
{
}

void EnrolledInfoTest::SetUp()
{
}

void EnrolledInfoTest::TearDown()
{
}

HWTEST_F(EnrolledInfoTest, GetUserId, TestSize.Level0)
{
    int32_t userId = 100;
    HdiEnrolledInfo info = {
        .enrolledId = 200,
        .authType = static_cast<HdiAuthType>(1),
    };
    EnrolledInfoImpl enrolledInfoImpl(userId, info);
    int32_t ret = enrolledInfoImpl.GetUserId();
    EXPECT_EQ(ret, userId);
}

HWTEST_F(EnrolledInfoTest, GetAuthType, TestSize.Level0)
{
    int32_t userId = 100;
    HdiEnrolledInfo info = {
        .enrolledId = 200,
        .authType = static_cast<HdiAuthType>(1),
    };
    EnrolledInfoImpl enrolledInfoImpl(userId, info);
    AuthType ret = enrolledInfoImpl.GetAuthType();
    EXPECT_EQ(ret, PIN);
}

HWTEST_F(EnrolledInfoTest, GetEnrolledId, TestSize.Level0)
{
    int32_t userId = 100;
    HdiEnrolledInfo info = {
        .enrolledId = 200,
        .authType = static_cast<HdiAuthType>(1),
    };
    EnrolledInfoImpl enrolledInfoImpl(userId, info);
    uint64_t ret = enrolledInfoImpl.GetEnrolledId();
    EXPECT_EQ(ret, 200U);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
