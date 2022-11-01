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

#include "driver_manager.h"
#include "mock_iauth_driver_hdi.h"
#include "mock_iauth_executor_hdi.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_EXECUTOR

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
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

HWTEST_F(DriverManagerUnitTest, DriverManagerTest_001, TestSize.Level0)
{
    std::string serviceName = "mockDriver";
    HdiConfig config = {};
    config.id = 10;
    config.driver = nullptr;
    std::map<std::string, HdiConfig> hdiName2Config;
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config), USERAUTH_SUCCESS);
    hdiName2Config.emplace(serviceName, config);
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config), USERAUTH_ERROR);
    EXPECT_EQ(DriverManager::GetInstance().GetDriverByServiceName(serviceName), nullptr);
    config.driver = Common::MakeShared<MockIAuthDriverHdi>();
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config), USERAUTH_ERROR);
    DriverManager::GetInstance().GetDriverByServiceName(serviceName);
    EXPECT_EQ(DriverManager::GetInstance().Start(hdiName2Config), USERAUTH_ERROR);
    DriverManager::GetInstance().OnFrameworkReady();
    DriverManager::GetInstance().SubscribeHdiDriverStatus();
    DriverManager::GetInstance().OnAllHdiDisconnect();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
