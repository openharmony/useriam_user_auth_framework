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

#include "user_idm_callback_proxy_test.h"

#include "iam_ptr.h"
#include "mock_remote_object.h"
#include "mock_user_idm_callback_service.h"
#include "user_idm_callback_proxy.h"
#include "widget_callback_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmCallbackProxyTest::SetUpTestCase()
{
}

void UserIdmCallbackProxyTest::TearDownTestCase()
{
}

void UserIdmCallbackProxyTest::SetUp()
{
}

void UserIdmCallbackProxyTest::TearDown()
{
}

HWTEST_F(UserIdmCallbackProxyTest, TestOnResult_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, IdmCallbackInterfaceCode::IDM_CALLBACK_ON_RESULT);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<IdmCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    int32_t result = 0;
    Attributes extraInfo;
    proxy->OnResult(result, extraInfo);
}

HWTEST_F(UserIdmCallbackProxyTest, TestOnAcquireInfo_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, IdmCallbackInterfaceCode::IDM_CALLBACK_ON_ACQUIRE_INFO);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<IdmCallbackProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    int32_t module = 10;
    int32_t acquireInfo = 20;
    Attributes extraInfo;
    proxy->OnAcquireInfo(module, acquireInfo, extraInfo);
}

HWTEST_F(UserIdmCallbackProxyTest, TestOnCredentialInfos_001, TestSize.Level0)
{
    auto service = Common::MakeShared<MockIdmGetCredInfoCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnCredentialInfos(_))
        .WillOnce(
            [](const std::vector<CredentialInfo> &credInfoList) {
                EXPECT_EQ(credInfoList.size(), 3);
                EXPECT_EQ(credInfoList[0].authType, PIN);
                EXPECT_EQ(credInfoList[1].authType, FACE);
                EXPECT_EQ(credInfoList[2].authType, FINGERPRINT);
                EXPECT_EQ(credInfoList[0].credentialId, 10);
                EXPECT_EQ(credInfoList[1].credentialId, 100);
                EXPECT_EQ(credInfoList[2].credentialId, 1000);
            }
        );

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                service->OnRemoteRequest(code, data, reply, option);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<IdmGetCredentialInfoProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    CredentialInfo info1 = {PIN, PIN_SIX, 10, 20};
    CredentialInfo info2 = {FACE, std::nullopt, 100, 200};
    CredentialInfo info3 = {FINGERPRINT, std::nullopt, 1000, 2000};
    std::vector<CredentialInfo> credInfoList = {info1, info2, info3};

    proxy->OnCredentialInfos(credInfoList);
}

HWTEST_F(UserIdmCallbackProxyTest, TestOnSecureUserInfo_001, TestSize.Level0)
{
    auto service = Common::MakeShared<MockIdmGetSecureUserInfoCallbackService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, OnSecureUserInfo(_))
        .WillOnce(
            [](const SecUserInfo &secUserInfo) {
                EXPECT_EQ(secUserInfo.secureUid, 1000);
                EXPECT_EQ(secUserInfo.enrolledInfo.size(), 2);
                EXPECT_EQ(secUserInfo.enrolledInfo[0].authType, FACE);
                EXPECT_EQ(secUserInfo.enrolledInfo[0].enrolledId, 10);
                EXPECT_EQ(secUserInfo.enrolledInfo[1].authType, FINGERPRINT);
                EXPECT_EQ(secUserInfo.enrolledInfo[1].enrolledId, 20);
            }
        );

    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                service->OnRemoteRequest(code, data, reply, option);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<IdmGetSecureUserInfoProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    SecUserInfo secUserInfo = {};
    secUserInfo.secureUid = 1000;
    secUserInfo.enrolledInfo = {{FACE, 10}, {FINGERPRINT, 20}};
    proxy->OnSecureUserInfo(secUserInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
