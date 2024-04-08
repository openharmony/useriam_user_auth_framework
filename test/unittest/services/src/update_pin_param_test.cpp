/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "update_pin_param_test.h"

#include "iam_common_defines.h"
#include "iam_ptr.h"
#include "update_pin_param_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
void UpdatePinParamTest::SetUpTestCase()
{
}

void UpdatePinParamTest::TearDownTestCase()
{
}

void UpdatePinParamTest::SetUp()
{
}

void UpdatePinParamTest::TearDown()
{
}

HWTEST_F(UpdatePinParamTest, UpdatePinParam001, TestSize.Level0)
{
    uint64_t credentialId = 1;
    std::vector<uint8_t> oldRootSecret = { 2, 3, 4 };
    std::vector<uint8_t> rootSecret = { 3, 4, 5 };
    std::vector<uint8_t> authToken = { 4, 5, 6 };
    auto pinInfo = Common::MakeShared<UpdatePinParamImpl>(credentialId, oldRootSecret, rootSecret, authToken);
    EXPECT_NE(pinInfo, nullptr);
    uint64_t testCredentialId = pinInfo->GetOldCredentialId();
    EXPECT_EQ(credentialId, testCredentialId);
    std::vector<uint8_t> testOldRootSecret = pinInfo->GetOldRootSecret();
    EXPECT_THAT(testOldRootSecret, ElementsAre(2, 3, 4));
    std::vector<uint8_t> testRootSecret = pinInfo->GetRootSecret();
    EXPECT_THAT(testRootSecret, ElementsAre(3, 4, 5));
    std::vector<uint8_t> testAuthToken = pinInfo->GetAuthToken();
    EXPECT_THAT(testAuthToken, ElementsAre(4, 5, 6));
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS