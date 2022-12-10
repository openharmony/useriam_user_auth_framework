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

#include "user_idm_callback_proxy_test.h"

#include "iam_ptr.h"
#include "mock_credential_info.h"
#include "mock_remote_object.h"
#include "mock_secure_user_info.h"
#include "user_idm_callback_proxy.h"

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
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, IdmCallbackInterface::IDM_CALLBACK_ON_RESULT);
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
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, IdmCallbackInterface::IDM_CALLBACK_ON_ACQUIRE_INFO);
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
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, IdmGetCredInfoCallbackInterface::ON_GET_INFO);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<IdmGetCredentialInfoProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    std::vector<std::shared_ptr<IdmGetCredInfoCallbackInterface::CredentialInfo>> infoList;
    infoList.push_back(nullptr);
    PinSubType subType = PIN_SIX;
    proxy->OnCredentialInfos(infoList, subType);

    infoList.clear();
    auto credInfo = Common::MakeShared<MockCredentialInfo>();
    EXPECT_NE(credInfo, nullptr);
    infoList.push_back(credInfo);

    EXPECT_CALL(*credInfo, GetCredentialId()).WillOnce(Return(20));
    EXPECT_CALL(*credInfo, GetTemplateId()).WillOnce(Return(30));
    EXPECT_CALL(*credInfo, GetAuthType()).WillOnce(Return(PIN));

    proxy->OnCredentialInfos(infoList, subType);
}

HWTEST_F(UserIdmCallbackProxyTest, TestOnSecureUserInfo_001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
    EXPECT_CALL(*obj, SendRequest(_, _, _, _))
        .WillOnce(
            [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
                EXPECT_EQ(code, IdmGetSecureUserInfoCallbackInterface::ON_GET_SEC_INFO);
                return OHOS::NO_ERROR;
            }
        );
    
    auto proxy = Common::MakeShared<IdmGetSecureUserInfoProxy>(obj);
    EXPECT_NE(proxy, nullptr);

    std::shared_ptr<IdmGetSecureUserInfoCallbackInterface::SecureUserInfo> info = nullptr;
    proxy->OnSecureUserInfo(info);

    std::vector<std::shared_ptr<IdmGetSecureUserInfoCallbackInterface::EnrolledInfo>> enrolledInfos;
    enrolledInfos.push_back(nullptr);
    auto testUserInfo = Common::MakeShared<MockSecureUserInfo>();
    EXPECT_NE(testUserInfo, nullptr);
    EXPECT_CALL(*testUserInfo, GetSecUserId()).WillOnce(Return(10));
    EXPECT_CALL(*testUserInfo, GetEnrolledInfo()).WillOnce(Return(enrolledInfos));

    proxy->OnSecureUserInfo(testUserInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
