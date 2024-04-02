/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "user_info_test.h"

#include "iam_common_defines.h"
#include "user_info_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserInfoTest::SetUpTestCase()
{
}

void UserInfoTest::TearDownTestCase()
{
}

void UserInfoTest::SetUp()
{
}

void UserInfoTest::TearDown()
{
}

HWTEST_F(UserInfoTest, GetUserId, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    UserInfo info = {};
    UserInfoImpl UserInfoImpl(userId, info);
    int32_t ret = UserInfoImpl.GetUserId();
    EXPECT_EQ(ret, userId);
}

HWTEST_F(UserInfoTest, GetPinSubType, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    constexpr PinSubType pinSubType = PIN_MIXED;
    constexpr uint64_t secUserId = 200;
    UserInfo info = {
        .secureUid = secUserId,
        .pinSubType = static_cast<OHOS::HDI::UserAuth::V2_0::PinSubType>(pinSubType),
    };
    UserInfoImpl UserInfoImpl(userId, info);
    EXPECT_EQ(UserInfoImpl.GetPinSubType(), pinSubType);
}

HWTEST_F(UserInfoTest, GetSecUserId, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    constexpr PinSubType pinSubType = PIN_MIXED;
    constexpr uint64_t secUserId = 200;
    UserInfo info = {
        .secureUid = secUserId,
        .pinSubType = static_cast<OHOS::HDI::UserAuth::V2_0::PinSubType>(pinSubType),
    };
    UserInfoImpl UserInfoImpl(userId, info);
    uint64_t ret = UserInfoImpl.GetSecUserId();
    EXPECT_EQ(ret, secUserId);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
