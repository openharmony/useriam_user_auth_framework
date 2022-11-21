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

#include <gtest/gtest.h>

#include "context_callback_impl.h"
#include "iam_ptr.h"
#include "mock_user_auth_callback.h"
#include "mock_user_idm_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace std;
using namespace testing;
using namespace testing::ext;

class ContextCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void ContextCallbackImplTest::SetUpTestCase()
{
}

void ContextCallbackImplTest::TearDownTestCase()
{
}

void ContextCallbackImplTest::SetUp()
{
}

void ContextCallbackImplTest::TearDown()
{
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserAuthNull, TestSize.Level0)
{
    sptr<UserAuthCallbackInterface> callback = nullptr;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ASSERT_EQ(contextCallback, nullptr);
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserIdmNull, TestSize.Level0)
{
    sptr<IdmCallbackInterface> callback = nullptr;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ASSERT_EQ(contextCallback, nullptr);
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserAuth, TestSize.Level0)
{
    int32_t testResult = 66;
    auto testAttr = Common::MakeShared<Attributes>();
    ASSERT_TRUE(testAttr != nullptr);

    sptr<MockUserAuthCallback> mockCallback = new (nothrow) MockUserAuthCallback();
    ASSERT_TRUE(mockCallback != nullptr);
    EXPECT_CALL(*mockCallback, OnResult(_, _))
        .Times(Exactly(1))
        .WillOnce([&testResult, &testAttr](int32_t result, const Attributes &reqRet) {
            EXPECT_TRUE(testResult == result);
            EXPECT_TRUE(&reqRet == testAttr.get());
        });
    sptr<UserAuthCallbackInterface> callback = mockCallback;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ASSERT_NE(contextCallback, nullptr);
    contextCallback->OnAcquireInfo(static_cast<ExecutorRole>(0), 0, {});
    contextCallback->OnResult(testResult, *testAttr);
}

HWTEST_F(ContextCallbackImplTest, ContextCallbackImplUserIdmOnResult, TestSize.Level0)
{
    int32_t testResult = 66;
    std::vector<uint8_t> testMsg = {1, 2, 3, 4};
    auto testAttr = Common::MakeShared<Attributes>();
    ASSERT_TRUE(testAttr != nullptr);
    EXPECT_TRUE(testAttr->SetInt32Value(Attributes::ATTR_REMAIN_TIMES, 2));
    EXPECT_TRUE(testAttr->SetInt32Value(Attributes::ATTR_FREEZING_TIME, 40));

    auto notify = [](const ContextCallbackNotifyListener::MetaData &metaData) { return; };
    ContextCallbackNotifyListener::GetInstance().AddNotifier(notify);
    ContextCallbackNotifyListener::GetInstance().AddNotifier(nullptr);

    sptr<MockIdmCallback> mockCallback = new (nothrow) MockIdmCallback();
    ASSERT_TRUE(mockCallback != nullptr);
    EXPECT_CALL(*mockCallback, OnResult(_, _)).Times(1);
    EXPECT_CALL(*mockCallback, OnAcquireInfo(_, _, _)).Times(1);
    sptr<IdmCallbackInterface> callback = mockCallback;
    auto contextCallback = ContextCallback::NewInstance(callback, TRACE_ADD_CREDENTIAL);
    ASSERT_NE(contextCallback, nullptr);
    contextCallback->OnAcquireInfo(static_cast<ExecutorRole>(0), 0, testMsg);
    contextCallback->OnResult(testResult, *testAttr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
