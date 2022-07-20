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

#include "credential_info_test.h"
#include "credential_info_impl.h"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
using HdiCredential = OHOS::HDI::UserAuth::V1_0::CredentialInfo;

void CredentialInfoTest::SetUpTestCase()
{
}

void CredentialInfoTest::TearDownTestCase()
{
}

void CredentialInfoTest::SetUp()
{
}

void CredentialInfoTest::TearDown()
{
}

HWTEST_F(CredentialInfoTest, GetCredentialId, TestSize.Level0)
{
    int32_t userId = 100;
    HdiCredential info = {
        .credentialId = 1,
        .executorIndex = 2,
        .templateId = 3,
        .authType = static_cast<OHOS::HDI::UserAuth::V1_0::AuthType>(4),
        .executorMatcher = 5,
        .executorSensorHint = 6,
    };

    CredentialInfoImpl CredentialInfoImpl(userId, info);
    uint64_t ret = CredentialInfoImpl.GetCredentialId();
    EXPECT_EQ(ret, info.credentialId);
}

HWTEST_F(CredentialInfoTest, GetUserId, TestSize.Level0)
{
    int32_t userId = 100;
    HdiCredential info = {
        .credentialId = 1,
        .executorIndex = 2,
        .templateId = 3,
        .authType = static_cast<OHOS::HDI::UserAuth::V1_0::AuthType>(4),
        .executorMatcher = 5,
        .executorSensorHint = 6,
    };
    CredentialInfoImpl CredentialInfoImpl(userId, info);
    int32_t ret = CredentialInfoImpl.GetUserId();
    EXPECT_EQ(ret, userId);
}

HWTEST_F(CredentialInfoTest, GetExecutorIndex, TestSize.Level0)
{
    int32_t userId = 100;
    HdiCredential info = {
        .credentialId = 1,
        .executorIndex = 2,
        .templateId = 3,
        .authType = static_cast<OHOS::HDI::UserAuth::V1_0::AuthType>(4),
        .executorMatcher = 5,
        .executorSensorHint = 6,
    };
    CredentialInfoImpl CredentialInfoImpl(userId, info);
    uint64_t ret = CredentialInfoImpl.GetExecutorIndex();
    EXPECT_EQ(ret, info.executorIndex);
}

HWTEST_F(CredentialInfoTest, GetTemplateId, TestSize.Level0)
{
    int32_t userId = 100;
    HdiCredential info = {
        .credentialId = 1,
        .executorIndex = 2,
        .templateId = 3,
        .authType = static_cast<OHOS::HDI::UserAuth::V1_0::AuthType>(4),
        .executorMatcher = 5,
        .executorSensorHint = 6,
    };
    CredentialInfoImpl CredentialInfoImpl(userId, info);
    uint64_t ret = CredentialInfoImpl.GetTemplateId();
    EXPECT_EQ(ret, info.templateId);
}

HWTEST_F(CredentialInfoTest, GetAuthType, TestSize.Level0)
{
    int32_t userId = 100;
    HdiCredential info = {
        .credentialId = 1,
        .executorIndex = 2,
        .templateId = 3,
        .authType = static_cast<OHOS::HDI::UserAuth::V1_0::AuthType>(4),
        .executorMatcher = 5,
        .executorSensorHint = 6,
    };
    CredentialInfoImpl CredentialInfoImpl(userId, info);
    AuthType ret = CredentialInfoImpl.GetAuthType();
    EXPECT_EQ(static_cast<uint32_t>(ret), static_cast<uint32_t>(info.authType));
}

HWTEST_F(CredentialInfoTest, GetExecutorSensorHint, TestSize.Level0)
{
    int32_t userId = 100;
    HdiCredential info = {
        .credentialId = 1,
        .executorIndex = 2,
        .templateId = 3,
        .authType = static_cast<OHOS::HDI::UserAuth::V1_0::AuthType>(4),
        .executorMatcher = 5,
        .executorSensorHint = 6,
    };
    CredentialInfoImpl CredentialInfoImpl(userId, info);
    uint32_t ret = CredentialInfoImpl.GetExecutorSensorHint();
    EXPECT_EQ(ret, info.executorSensorHint);
}

HWTEST_F(CredentialInfoTest, GetExecutorMatcher, TestSize.Level0)
{
    int32_t userId = 100;
    HdiCredential info = {
        .credentialId = 1,
        .executorIndex = 2,
        .templateId = 3,
        .authType = static_cast<OHOS::HDI::UserAuth::V1_0::AuthType>(4),
        .executorMatcher = 5,
        .executorSensorHint = 6,
    };
    CredentialInfoImpl CredentialInfoImpl(userId, info);
    uint32_t ret = CredentialInfoImpl.GetExecutorMatcher();
    EXPECT_EQ(ret, info.executorMatcher);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
