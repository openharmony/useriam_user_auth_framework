/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "auth_widget_helper.h"

#include <future>

#include "iam_common_defines.h"
#include "iam_logger.h"
#include "mock_iuser_auth_interface.h"
#include "mock_schedule_node.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {

class AuthWidgetHelperTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void AuthWidgetHelperTest::SetUpTestCase()
{
}

void AuthWidgetHelperTest::TearDownTestCase()
{
}

void AuthWidgetHelperTest::SetUp()
{
}

void AuthWidgetHelperTest::TearDown()
{
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam001, TestSize.Level0)
{
    AuthParam authParam;
    authParam.authType.push_back(FACE);
    authParam.authType.push_back(ALL);
    authParam.authType.push_back(PIN);
    authParam.authType.push_back(FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParam widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType;
    EXPECT_TRUE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam002, TestSize.Level0)
{
    AuthParam authParam;
    authParam.authType.push_back(FACE);
    authParam.authType.push_back(ALL);
    authParam.authType.push_back(PIN);
    authParam.authType.push_back(FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParam widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authType;
    EXPECT_FALSE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestCheckValidSolution, TestSize.Level0)
{
    int32_t userId = 1;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(FACE);
    authTypeList.push_back(ALL);
    authTypeList.push_back(PIN);
    authTypeList.push_back(FINGERPRINT);
    AuthTrustLevel atl = ATL3;
    std::vector<AuthType> validTypeList;
    EXPECT_FALSE(AuthWidgetHelper::CheckValidSolution(userId, authTypeList, atl, validTypeList));
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestCheckReuseUnlockResult001, TestSize.Level0)
{
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    Attributes extraInfo;
    AuthParam authParam;
    authParam.reuseUnlockResult.isReuse = false;
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), INVALID_PARAMETERS);

    authParam.reuseUnlockResult.isReuse = true;
    authParam.reuseUnlockResult.reuseDuration = 0;
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), INVALID_PARAMETERS);

    authParam.reuseUnlockResult.reuseDuration = 6 * 60 * 1000;
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), INVALID_PARAMETERS);
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestCheckReuseUnlockResult002, TestSize.Level0)
{
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    Attributes extraInfo;
    AuthParam authParam;
    authParam.reuseUnlockResult.isReuse = true;
    authParam.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;
    authParam.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _)).Times(3);
    ON_CALL(*mockHdi, CheckReuseUnlockResult)
        .WillByDefault(
            [](const HdiReuseUnlockInfo &info, std::vector<uint8_t> &token) {
                return HDF_FAILURE;
            }
        );
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), HDF_FAILURE);
    ON_CALL(*mockHdi, CheckReuseUnlockResult)
        .WillByDefault(
            [](const HdiReuseUnlockInfo &info, std::vector<uint8_t> &token) {
                return HDF_SUCCESS;
            }
        );
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), GENERAL_ERROR);
    ON_CALL(*mockHdi, CheckReuseUnlockResult)
        .WillByDefault(
            [](const HdiReuseUnlockInfo &info, std::vector<uint8_t> &token) {
                token.push_back(1);
                return HDF_SUCCESS;
            }
        );
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS