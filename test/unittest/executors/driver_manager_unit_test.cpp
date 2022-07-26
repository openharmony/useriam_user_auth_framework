/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "iam_logger.h"
#include "iam_ptr.h"

#include "mock_iauth_driver_hdi.h"
#include "mock_iauth_executor_hdi.h"

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_USER_AUTH_EXECUTOR

using namespace testing;
using namespace testing::ext;
using namespace OHOS::UserIAM::Common;

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using namespace OHOS::UserIam::UserAuth;
class DriverManagerUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DriverManagerUnitTest::SetUpTestCase()
{
}

void DriverManagerUnitTest::TearDownTestCase()
{
}

void DriverManagerUnitTest::SetUp()
{
}

void DriverManagerUnitTest::TearDown()
{
}

HWTEST_F(DriverManagerUnitTest, UserAuthDriverManager_GetExecutorListTest_001, TestSize.Level0)
{
    EXPECT_TRUE(0 == 0);
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
