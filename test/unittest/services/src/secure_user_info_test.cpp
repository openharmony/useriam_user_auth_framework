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

#include "secure_user_info_test.h"

#include "iam_common_defines.h"
#include "secure_user_info_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SecureUserInfoTest::SetUpTestCase()
{
}

void SecureUserInfoTest::TearDownTestCase()
{
}

void SecureUserInfoTest::SetUp()
{
}

void SecureUserInfoTest::TearDown()
{
}

HWTEST_F(SecureUserInfoTest, GetUserId, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    constexpr PinSubType pinSubType = PIN_MIXED;
    constexpr uint64_t secUserId = 200;
    std::vector<std::shared_ptr<EnrolledInfo>> info = {nullptr};
    SecureUserInfoImpl secureUserInfoImpl(userId, pinSubType, secUserId, info);
    int32_t ret = secureUserInfoImpl.GetUserId();
    EXPECT_EQ(ret, userId);
}

HWTEST_F(SecureUserInfoTest, GetPinSubType, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    constexpr PinSubType pinSubType = PIN_MIXED;
    constexpr uint64_t secUserId = 200;
    std::vector<std::shared_ptr<EnrolledInfo>> info = {nullptr};
    SecureUserInfoImpl secureUserInfoImpl(userId, pinSubType, secUserId, info);
    EXPECT_EQ(secureUserInfoImpl.GetPinSubType(), pinSubType);
}

HWTEST_F(SecureUserInfoTest, GetSecUserId, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    constexpr PinSubType pinSubType = PIN_MIXED;
    constexpr uint64_t secUserId = 200;
    std::vector<std::shared_ptr<EnrolledInfo>> info = {nullptr};
    SecureUserInfoImpl secureUserInfoImpl(userId, pinSubType, secUserId, info);
    uint64_t ret = secureUserInfoImpl.GetSecUserId();
    EXPECT_EQ(ret, secUserId);
}

HWTEST_F(SecureUserInfoTest, GetEnrolledInfo, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    constexpr PinSubType pinSubType = PIN_MIXED;
    constexpr uint64_t secUserId = 200;
    std::vector<std::shared_ptr<EnrolledInfo>> info = {nullptr};
    SecureUserInfoImpl secureUserInfoImpl(userId, pinSubType, secUserId, info);
    auto ret = secureUserInfoImpl.GetEnrolledInfo();
    EXPECT_EQ(ret, info);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
