/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "callback_manager_impl_test.h"
#include "callback_manager.h"

#include "widget_callback_service.h"
#include "mock_iuser_auth_widget_callback.h"
#include "iam_ptr.h"
#include "user_idm_callback_service.h"
#include "mock_user_idm_client_callback.h"

#include "user_auth_callback_service.h"
#include "mock_user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void CallbackManagerImplTest::SetUpTestCase()
{
}

void CallbackManagerImplTest::TearDownTestCase()
{
}

void CallbackManagerImplTest::SetUp()
{
}

void CallbackManagerImplTest::TearDown()
{
}

HWTEST_F(CallbackManagerImplTest, CallbackManagerImplOnServiceDeath001, TestSize.Level0)
{
    auto widgetCallback = Common::MakeShared<MockIUserAuthWidgetCallback>();
    EXPECT_NE(widgetCallback, nullptr);
    auto service = Common::MakeShared<WidgetCallbackService>(widgetCallback);
    CallbackManager::GetInstance().OnServiceDeath();
    EXPECT_NE(service, nullptr);
}

HWTEST_F(CallbackManagerImplTest, CallbackManagerImplOnServiceDeath002, TestSize.Level0)
{
    auto idmClientCallback = Common::MakeShared<MockUserIdmClientCallback>();
    EXPECT_NE(idmClientCallback, nullptr);
    auto service = Common::MakeShared<IdmCallbackService>(idmClientCallback);
    CallbackManager::GetInstance().OnServiceDeath();
    EXPECT_NE(service, nullptr);
}

HWTEST_F(CallbackManagerImplTest, CallbackManagerImplOnServiceDeath003, TestSize.Level0)
{
    auto getCredInfoCallback = Common::MakeShared<MockGetCredentialInfoCallback>();
    EXPECT_NE(getCredInfoCallback, nullptr);
    auto service = Common::MakeShared<IdmGetCredInfoCallbackService>(getCredInfoCallback);
    CallbackManager::GetInstance().OnServiceDeath();
    EXPECT_NE(service, nullptr);
}

HWTEST_F(CallbackManagerImplTest, CallbackManagerImplOnServiceDeath004, TestSize.Level0)
{
    auto getSecInfoCallback = Common::MakeShared<MockGetSecUserInfoCallback>();
    EXPECT_NE(getSecInfoCallback, nullptr);
    auto service = Common::MakeShared<IdmGetSecureUserInfoCallbackService>(getSecInfoCallback);
    CallbackManager::GetInstance().OnServiceDeath();
    EXPECT_NE(service, nullptr);
}

HWTEST_F(CallbackManagerImplTest, CallbackManagerImplOnServiceDeath005, TestSize.Level0)
{
    auto authCallback = Common::MakeShared<MockAuthenticationCallback>();
    EXPECT_NE(authCallback, nullptr);
    auto service = Common::MakeShared<UserAuthCallbackService>(authCallback);
    CallbackManager::GetInstance().OnServiceDeath();
    EXPECT_NE(service, nullptr);
}

HWTEST_F(CallbackManagerImplTest, CallbackManagerImplOnServiceDeath006, TestSize.Level0)
{
    auto identifyCallback = Common::MakeShared<MockIdentificationCallback>();
    EXPECT_NE(identifyCallback, nullptr);
    auto service = Common::MakeShared<UserAuthCallbackService>(identifyCallback);
    CallbackManager::GetInstance().OnServiceDeath();
    EXPECT_NE(service, nullptr);
}

HWTEST_F(CallbackManagerImplTest, CallbackManagerImplOnServiceDeath007, TestSize.Level0)
{
    auto getPropCallback = Common::MakeShared<MockGetPropCallback>();
    EXPECT_NE(getPropCallback, nullptr);
    auto service = Common::MakeShared<GetExecutorPropertyCallbackService>(getPropCallback);
    CallbackManager::GetInstance().OnServiceDeath();
    EXPECT_NE(service, nullptr);
}

HWTEST_F(CallbackManagerImplTest, CallbackManagerImplOnServiceDeath008, TestSize.Level0)
{
    auto setPropCallback = Common::MakeShared<MockSetPropCallback>();
    EXPECT_NE(setPropCallback, nullptr);
    auto service = Common::MakeShared<SetExecutorPropertyCallbackService>(setPropCallback);
    CallbackManager::GetInstance().OnServiceDeath();
    EXPECT_NE(service, nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS