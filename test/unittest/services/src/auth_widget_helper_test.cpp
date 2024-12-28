/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "mock_iuser_auth_interface.h"
#include "mock_schedule_node.h"
#include "mock_resource_node.h"
#include "resource_node_pool.h"
#include "iam_ptr.h"

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
    AuthParamInner authParam;
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(ALL);
    authParam.authTypes.push_back(PIN);
    authParam.authTypes.push_back(FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType;
    EXPECT_TRUE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam002, TestSize.Level0)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(FACE);
    authParam.authTypes.push_back(ALL);
    authParam.authTypes.push_back(PIN);
    authParam.authTypes.push_back(FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authTypes;
    EXPECT_FALSE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam003, TestSize.Level0)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(PIN);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authTypes;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillOnce(Return(HDF_FAILURE));
    EXPECT_FALSE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillOnce(Return(HDF_SUCCESS));
    EXPECT_FALSE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    constexpr uint64_t executorIndex = 61;
    auto fillUpInfos = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo temp = {
            .credentialId = 1,
            .executorIndex = executorIndex,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(1),
            .executorMatcher = 2,
            .executorSensorHint = 3,
        };
        infos.push_back(temp);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    EXPECT_FALSE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, PIN, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_FALSE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam004, TestSize.Level0)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(PRIVATE_PIN);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authTypes;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    constexpr uint64_t executorIndex = 61;
    auto fillUpInfos = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo temp = {
            .credentialId = 1,
            .executorIndex = executorIndex,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(16),
            .executorMatcher = 2,
            .executorSensorHint = 3,
        };
        infos.push_back(temp);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    auto resourceNode = MockResourceNode::CreateWithExecuteIndex(executorIndex, PRIVATE_PIN, ALL_IN_ONE);
    EXPECT_NE(resourceNode, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_FALSE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam005, TestSize.Level0)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authTypes;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    constexpr uint64_t executorIndex = 61;
    auto fillUpInfos = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo temp = {
            .credentialId = 1,
            .executorIndex = executorIndex,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(4),
            .executorMatcher = 2,
            .executorSensorHint = 3,
        };
        infos.push_back(temp);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(executorIndex));
    EXPECT_NE(resourceNode, nullptr);
    ON_CALL(*resourceNode, GetProperty).WillByDefault(
        [](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, 10001);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 5);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
            return SUCCESS;
        }
    );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_TRUE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam006, TestSize.Level0)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authTypes;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    constexpr uint64_t executorIndex = 61;
    auto fillUpInfos = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo temp = {
            .credentialId = 1,
            .executorIndex = executorIndex,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(4),
            .executorMatcher = 2,
            .executorSensorHint = 3,
        };
        infos.push_back(temp);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(executorIndex));
    EXPECT_NE(resourceNode, nullptr);
    ON_CALL(*resourceNode, GetProperty).WillByDefault(
        [](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, 10001);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 5);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
            return HDF_ERR_INVALID_PARAM;
        }
    );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_TRUE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam007, TestSize.Level0)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(FINGERPRINT);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authTypes;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    constexpr uint64_t executorIndex = 61;
    auto fillUpInfos = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo temp = {
            .credentialId = 1,
            .executorIndex = executorIndex,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(4),
            .executorMatcher = 2,
            .executorSensorHint = 3,
        };
        infos.push_back(temp);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(executorIndex));
    EXPECT_NE(resourceNode, nullptr);
    ON_CALL(*resourceNode, GetProperty).WillByDefault(
        [](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, 10001);
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 5);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
            return SUCCESS;
        }
    );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_FALSE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam008, TestSize.Level0)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(PIN);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    widgetParam.windowMode = WindowModeType::DIALOG_BOX;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authTypes;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    constexpr uint64_t executorIndex = 61;
    auto fillUpInfos = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo temp = {
            .credentialId = 1,
            .executorIndex = executorIndex,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(1),
            .executorMatcher = 2,
            .executorSensorHint = 3,
        };
        infos.push_back(temp);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(executorIndex));
    EXPECT_NE(resourceNode, nullptr);
    ON_CALL(*resourceNode, GetProperty).WillByDefault(
        [](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, 10001);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 5);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
            return SUCCESS;
        }
    );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_TRUE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestInitWidgetContextParam009, TestSize.Level0)
{
    AuthParamInner authParam;
    authParam.authTypes.push_back(PRIVATE_PIN);
    authParam.authTrustLevel = ATL2;
    WidgetParamInner widgetParam;
    widgetParam.title = "使用密码验证";
    widgetParam.navigationButtonText = "确定";
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    std::vector<AuthType> validType = authParam.authTypes;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    constexpr uint64_t executorIndex = 61;
    auto fillUpInfos = [](std::vector<HdiCredentialInfo> &list) {
        std::vector<HdiCredentialInfo> infos = {};
        HdiCredentialInfo temp = {
            .credentialId = 1,
            .executorIndex = executorIndex,
            .templateId = 3,
            .authType = static_cast<HdiAuthType>(16),
            .executorMatcher = 2,
            .executorSensorHint = 3,
        };
        infos.push_back(temp);
        list.swap(infos);
    };
    EXPECT_CALL(*mockHdi, GetCredential(_, _, _)).WillRepeatedly(DoAll(WithArg<2>(fillUpInfos), Return(0)));
    auto resourceNode = Common::MakeShared<MockResourceNode>();
    EXPECT_CALL(*resourceNode, GetExecutorIndex()).WillRepeatedly(Return(executorIndex));
    EXPECT_NE(resourceNode, nullptr);
    ON_CALL(*resourceNode, GetProperty).WillByDefault(
        [](const Attributes &condition, Attributes &values) {
            values.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, 10001);
            values.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
            values.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 5);
            values.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
            return SUCCESS;
        }
    );
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(resourceNode));
    EXPECT_TRUE(AuthWidgetHelper::InitWidgetContextParam(authParam, validType, widgetParam, para));
    EXPECT_TRUE(ResourceNodePool::Instance().Delete(executorIndex));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestCheckValidSolution001, TestSize.Level0)
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

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestCheckValidSolution002, TestSize.Level0)
{
    int32_t userId = 1;
    std::vector<AuthType> authTypeList;
    authTypeList.push_back(FACE);
    authTypeList.push_back(ALL);
    authTypeList.push_back(PIN);
    authTypeList.push_back(FINGERPRINT);
    AuthTrustLevel atl = ATL3;
    std::vector<AuthType> validTypeList;
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, GetValidSolution(_, _, _, _)).WillOnce(Return(HDF_FAILURE));
    EXPECT_TRUE(AuthWidgetHelper::CheckValidSolution(userId, authTypeList, atl, validTypeList));
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestCheckReuseUnlockResult001, TestSize.Level0)
{
    ContextFactory::AuthWidgetContextPara para;
    para.userId = 1;
    Attributes extraInfo;
    AuthParamInner authParam;
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
    AuthParamInner authParam;
    authParam.reuseUnlockResult.isReuse = true;
    authParam.reuseUnlockResult.reuseDuration = 5 * 60 * 1000;
    authParam.reuseUnlockResult.reuseMode = AUTH_TYPE_RELEVANT;

    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*mockHdi, CheckReuseUnlockResult(_, _)).Times(5);
    ON_CALL(*mockHdi, CheckReuseUnlockResult)
        .WillByDefault(Return(HDF_FAILURE));
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), HDF_FAILURE);
    ON_CALL(*mockHdi, CheckReuseUnlockResult)
        .WillByDefault(
            [](const HdiReuseUnlockParam &info, HdiReuseUnlockInfo &reuseInfo) {
                std::vector<uint8_t> token;
                token.push_back(1);
                return HDF_SUCCESS;
            }
        );
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), HDF_SUCCESS);
    ON_CALL(*mockHdi, CheckReuseUnlockResult)
        .WillByDefault(Return(HDF_SUCCESS));
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), SUCCESS);

    para.sdkVersion = 10001;
    authParam.authTypes.push_back(FINGERPRINT);
    ON_CALL(*mockHdi, CheckReuseUnlockResult).WillByDefault(Return(HDF_SUCCESS));
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), SUCCESS);

    authParam.reuseUnlockResult.isReuse = true;
    authParam.reuseUnlockResult.reuseDuration = 4 * 60 * 1000;
    authParam.reuseUnlockResult.reuseMode = CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT;
    EXPECT_EQ(AuthWidgetHelper::CheckReuseUnlockResult(para, authParam, extraInfo), SUCCESS);
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(AuthWidgetHelperTest, AuthWidgetHelperTestParseAttributes001, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, 10001);
    attributes.SetStringValue(Attributes::ATTR_SENSOR_INFO, "test");
    attributes.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 5);
    attributes.SetInt32Value(Attributes::ATTR_FREEZING_TIME, 0);
    AuthType authType = PIN;
    ContextFactory::AuthProfile authProfile;
    EXPECT_EQ(AuthWidgetHelper::ParseAttributes(attributes, authType, authProfile), true);
    authType = ALL;
    EXPECT_EQ(AuthWidgetHelper::ParseAttributes(attributes, authType, authProfile), true);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS