/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "remote_executor_proxy_test.h"

#include "iam_ptr.h"
#include "remote_executor_proxy.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ResourceExecutorProxyTest::SetUpTestCase()
{
}

void ResourceExecutorProxyTest::TearDownTestCase()
{
}

void ResourceExecutorProxyTest::SetUp()
{
}

void ResourceExecutorProxyTest::TearDown()
{
}

HWTEST_F(ResourceExecutorProxyTest, StartTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);
    EXPECT_EQ(proxy->Start(), ResultCode::GENERAL_ERROR);
}

HWTEST_F(ResourceExecutorProxyTest, OnMessageTest001, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    std::string srcEndPoint = "";
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    request->SetInt32Value(Attributes::ATTR_MSG_TYPE, EXECUTOR_SEND_DATA);
    std::shared_ptr<Attributes> reply = Common::MakeShared<Attributes>();
    EXPECT_NO_THROW(proxy->OnMessage(connectionName, srcEndPoint, request, reply));
}

HWTEST_F(ResourceExecutorProxyTest, OnMessageTest002, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    std::string srcEndPoint = "";
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    request->SetInt32Value(Attributes::ATTR_MSG_TYPE, EXECUTOR_FINISH);
    std::shared_ptr<Attributes> reply = Common::MakeShared<Attributes>();
    EXPECT_NO_THROW(proxy->OnMessage(connectionName, srcEndPoint, request, reply));
}

HWTEST_F(ResourceExecutorProxyTest, OnMessageTest003, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    std::string srcEndPoint = "";
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    request->SetInt32Value(Attributes::ATTR_MSG_TYPE, KEEP_ALIVE);
    std::shared_ptr<Attributes> reply = Common::MakeShared<Attributes>();
    EXPECT_NO_THROW(proxy->OnMessage(connectionName, srcEndPoint, request, reply));
}

HWTEST_F(ResourceExecutorProxyTest, OnConnectStatusTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    ConnectStatus connectStatus = {};
    EXPECT_NO_THROW(proxy->OnConnectStatus(connectionName, connectStatus));
}

HWTEST_F(ResourceExecutorProxyTest, OnMessengerReadyTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    std::shared_ptr<ExecutorMessenger> messenger;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIdList;
    EXPECT_NO_THROW(proxy->OnMessengerReady(messenger, publicKey, templateIdList));
}

HWTEST_F(ResourceExecutorProxyTest, OnBeginExecuteTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    uint64_t scheduleId = 0;
    std::vector<uint8_t> publicKey;
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    Attributes command = {};
    std::vector<uint8_t> value;
    command.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, value);
    EXPECT_EQ(proxy->OnBeginExecute(scheduleId, publicKey, command), ResultCode::GENERAL_ERROR);
}

HWTEST_F(ResourceExecutorProxyTest, OnEndExecuteTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    uint64_t scheduleId = 0;
    Attributes command = {};
    EXPECT_EQ(proxy->OnEndExecute(scheduleId, command), ResultCode::GENERAL_ERROR);
}

HWTEST_F(ResourceExecutorProxyTest, OnSendDataTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    uint64_t scheduleId = 0;
    Attributes data = {};
    EXPECT_EQ(proxy->OnSendData(scheduleId, data), ResultCode::GENERAL_ERROR);
}

HWTEST_F(ResourceExecutorProxyTest, OnErrorFinishTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    uint64_t scheduleId = 0;
    EXPECT_NO_THROW(proxy->OnErrorFinish(scheduleId));
}

HWTEST_F(ResourceExecutorProxyTest, ProcSendDataMsgTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    Attributes data = {};
    uint64_t scheduleId = 0;
    data.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    int32_t dstRole = 0;
    data.SetInt32Value(Attributes::ATTR_SCHEDULE_ID, dstRole);
    EXPECT_EQ(proxy->ProcSendDataMsg(data), ResultCode::GENERAL_ERROR);
}

HWTEST_F(ResourceExecutorProxyTest, ProcFinishMsgTest, TestSize.Level0)
{
    std::string connectionName = "";
    ExecutorInfo registerInfo = {};
    auto proxy = Common::MakeShared<RemoteExecutorProxy>(connectionName, registerInfo);

    Attributes data = {};
    EXPECT_EQ(proxy->ProcFinishMsg(data), ResultCode::GENERAL_ERROR);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
