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

#include "co_auth_service_test.h"

#include "co_auth_service.h"
#include "iam_ptr.h"
#include "mock_executor_callback.h"
#include "mock_ipc_common.h"
#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "resource_node_pool.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

using HdiExecutorRegisterInfo = OHOS::HDI::UserAuth::V1_0::ExecutorRegisterInfo;

void CoAuthServiceTest::SetUpTestCase()
{
}

void CoAuthServiceTest::TearDownTestCase()
{
}

void CoAuthServiceTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void CoAuthServiceTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTest001, TestSize.Level0)
{
    sptr<ExecutorCallbackInterface> testCallback = new MockExecutorCallback();
    EXPECT_NE(testCallback, nullptr);
    sptr<MockExecutorCallback> tempCallback = static_cast<MockExecutorCallback *>(testCallback.GetRefPtr());
    EXPECT_NE(tempCallback, nullptr);

    CoAuthInterface::ExecutorRegisterInfo info = {};
    info.authType = FINGERPRINT;
    info.executorRole = SCHEDULER;
    info.executorSensorHint = 0;
    info.executorMatcher = 0;
    info.esl = ESL1;
    info.publicKey = {'a', 'b', 'c', 'd'};
    
    auto service = Common::MakeShared<CoAuthService>(1, true);
    EXPECT_NE(service, nullptr);
    auto mockHdi = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_NE(mockHdi, nullptr);
    EXPECT_CALL(*tempCallback, OnMessengerReady(_, _, _)).Times(1);
    EXPECT_CALL(*mockHdi, AddExecutor(_, _, _, _))
        .Times(2)
        .WillOnce(Return(HDF_FAILURE))
        .WillOnce(
            [](const HdiExecutorRegisterInfo &info, uint64_t &index, std::vector<uint8_t> &publicKey,
                std::vector<uint64_t> &templateIds) {
                index = 12345;
                return HDF_SUCCESS;
            }
        );
    EXPECT_CALL(*mockHdi, DeleteExecutor(_)).Times(1);
    IpcCommon::AddPermission(ACCESS_AUTH_RESPOOL);
    uint64_t executorIndex = service->ExecutorRegister(info, testCallback);
    EXPECT_EQ(executorIndex, 0);
    executorIndex = service->ExecutorRegister(info, testCallback);
    EXPECT_NE(executorIndex, 0);
    EXPECT_EQ(ResourceNodePool::Instance().Delete(executorIndex), true);
    IpcCommon::DeleteAllPermission();
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTest003, TestSize.Level0)
{
    auto service = Common::MakeShared<CoAuthService>(1, true);
    EXPECT_NE(service, nullptr);

    CoAuthInterface::ExecutorRegisterInfo info = {};
    sptr<ExecutorCallbackInterface> testCallback = nullptr;
    uint64_t executorIndex = service->ExecutorRegister(info, testCallback);
    EXPECT_EQ(executorIndex, 0);
}

HWTEST_F(CoAuthServiceTest, CoAuthServiceTest004, TestSize.Level0)
{
    int testFd1 = -1;
    int testFd2 = 1;
    std::vector<std::u16string> testArgs;

    auto service = Common::MakeShared<CoAuthService>(1, true);
    EXPECT_NE(service, nullptr);

    auto node = MockResourceNode::CreateWithExecuteIndex(20);
    EXPECT_NE(node, nullptr);
    EXPECT_TRUE(ResourceNodePool::Instance().Insert(node));

    EXPECT_EQ(service->Dump(testFd1, testArgs), INVALID_PARAMETERS);
    EXPECT_EQ(service->Dump(testFd2, testArgs), SUCCESS);
    testArgs.push_back(u"-h");
    EXPECT_EQ(service->Dump(testFd2, testArgs), SUCCESS);
    testArgs.clear();
    testArgs.push_back(u"-l");
    EXPECT_EQ(service->Dump(testFd2, testArgs), SUCCESS);
    testArgs.clear();
    testArgs.push_back(u"-k");
    EXPECT_EQ(service->Dump(testFd2, testArgs), GENERAL_ERROR);

    EXPECT_TRUE(ResourceNodePool::Instance().Delete(20));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS