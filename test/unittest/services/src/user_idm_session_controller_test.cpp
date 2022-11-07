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

#include "user_idm_session_controller_test.h"

#include "iam_common_defines.h"
#include "mock_iuser_auth_interface.h"
#include "user_idm_session_controller.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void UserIdmSessionControllerTest::SetUpTestCase()
{
}

void UserIdmSessionControllerTest::TearDownTestCase()
{
}

void UserIdmSessionControllerTest::SetUp()
{
}

void UserIdmSessionControllerTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
    UserIdmSessionController::Instance().ForceReset();
}

HWTEST_F(UserIdmSessionControllerTest, UserIdmServiceOpenSessionSuccess, TestSize.Level0)
{
    int32_t userId = 100;
    std::vector<uint8_t> challenge;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, OpenSession(userId, _)).WillRepeatedly(Return(SUCCESS));

    EXPECT_EQ(true, UserIdmSessionController::Instance().OpenSession(userId, challenge));
}

HWTEST_F(UserIdmSessionControllerTest, UserIdmServiceOpenSessionTwice, TestSize.Level0)
{
    int32_t userId1 = 100;
    int32_t userId2 = 100;
    int32_t userId3 = 200;
    std::vector<uint8_t> challenge;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, OpenSession(_, _)).WillRepeatedly(Return(SUCCESS));

    EXPECT_EQ(true, UserIdmSessionController::Instance().OpenSession(userId1, challenge));
    EXPECT_EQ(true, UserIdmSessionController::Instance().OpenSession(userId2, challenge));
    EXPECT_EQ(true, UserIdmSessionController::Instance().OpenSession(userId3, challenge));
}

HWTEST_F(UserIdmSessionControllerTest, UserIdmServiceOpenSessionFailed, TestSize.Level0)
{
    int32_t userId = 100;
    std::vector<uint8_t> challenge;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, OpenSession(userId, _)).WillRepeatedly(Return(GENERAL_ERROR));

    EXPECT_EQ(false, UserIdmSessionController::Instance().OpenSession(userId, challenge));
}

HWTEST_F(UserIdmSessionControllerTest, UserIdmServiceIsSessionOpened, TestSize.Level0)
{
    int32_t userId = 100;
    std::vector<uint8_t> nonce = {1, 3, 2, 5, 7};

    std::vector<uint8_t> challenge;

    auto fillUpChallenge = [&nonce](std::vector<uint8_t> &challenge) { challenge = nonce; };

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, OpenSession(userId, _)).WillRepeatedly(DoAll(WithArg<1>(fillUpChallenge), Return(SUCCESS)));

    EXPECT_EQ(false, UserIdmSessionController::Instance().IsSessionOpened(userId));

    EXPECT_EQ(true, UserIdmSessionController::Instance().OpenSession(userId, challenge));
    EXPECT_THAT(challenge, ElementsAreArray(nonce));

    EXPECT_EQ(true, UserIdmSessionController::Instance().IsSessionOpened(userId));
}

HWTEST_F(UserIdmSessionControllerTest, UserIdmServiceIsSessionClosedByUserId, TestSize.Level0)
{
    int32_t userId = 100;
    std::vector<uint8_t> nonce = {1, 3, 2, 5, 7};

    std::vector<uint8_t> challenge;

    auto fillUpChallenge = [&nonce](std::vector<uint8_t> &challenge) { challenge = nonce; };

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, OpenSession(userId, _)).WillRepeatedly(DoAll(WithArg<1>(fillUpChallenge), Return(SUCCESS)));
    EXPECT_CALL(*mock, CloseSession(userId))
        .WillOnce(Return(HDF_SUCCESS))
        .WillOnce(Return(HDF_FAILURE));

    EXPECT_EQ(true, UserIdmSessionController::Instance().OpenSession(userId, challenge));

    EXPECT_TRUE(UserIdmSessionController::Instance().CloseSession(userId));
    EXPECT_FALSE(UserIdmSessionController::Instance().CloseSession(userId));
}

HWTEST_F(UserIdmSessionControllerTest, UserIdmServiceIsSessionClosedByChallenge, TestSize.Level0)
{
    int32_t userId = 100;
    std::vector<uint8_t> nonce = {1, 3, 2, 5, 7};

    std::vector<uint8_t> challenge;

    auto fillUpChallenge = [&nonce](std::vector<uint8_t> &challenge) { challenge = nonce; };

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, OpenSession(userId, _)).WillRepeatedly(DoAll(WithArg<1>(fillUpChallenge), Return(SUCCESS)));
    EXPECT_CALL(*mock, CloseSession(userId)).WillRepeatedly(Return(SUCCESS));

    EXPECT_EQ(true, UserIdmSessionController::Instance().OpenSession(userId, challenge));

    EXPECT_EQ(true, UserIdmSessionController::Instance().CloseSession(userId));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS