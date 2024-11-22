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

#include "soft_bus_base_socket_test.h"
#include "soft_bus_base_socket.h"
#include "soft_bus_manager.h"
#include "remote_connect_listener_manager.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SoftBusBaseSocketTest::SetUpTestCase()
{
}

void SoftBusBaseSocketTest::TearDownTestCase()
{
}

void SoftBusBaseSocketTest::SetUp()
{
}

void SoftBusBaseSocketTest::TearDown()
{
}

class BaseSocketTest : public BaseSocket {
public:
    explicit BaseSocketTest(const int32_t socketId);
    ~BaseSocketTest();
    ResultCode SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback);

    void OnBind(int32_t socketId, PeerSocketInfo info);
    void OnShutdown(int32_t socketId, ShutdownReason reason);
    void OnBytes(int32_t socketId, const void *data, uint32_t dataLen);
    void OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount);

    std::string GetConnectionName() override;
    std::string GetNetworkId();
};

BaseSocketTest::BaseSocketTest(const int32_t socketId)
    : BaseSocket(socketId)
{
}

BaseSocketTest::~BaseSocketTest()
{
}

ResultCode BaseSocketTest::SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    return SUCCESS;
}

void BaseSocketTest::OnBind(int32_t socketId, PeerSocketInfo info)
{
    return;
}

void BaseSocketTest::OnShutdown(int32_t socketId, ShutdownReason reason)
{
    return;
}

void BaseSocketTest::OnBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    return;
}

void BaseSocketTest::OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount)
{
    return;
}

std::string BaseSocketTest::GetConnectionName()
{
    return "connectionName";
}

std::string BaseSocketTest::GetNetworkId()
{
    return "networkId";
}


HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestInsertMsgCallback, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    uint32_t messageSeq = 123;
    const std::string connectionName = "connectionName";
    MsgCallback callback;
    uint32_t timerId = 456;
    EXPECT_NO_THROW(baseSocket->InsertMsgCallback(messageSeq, connectionName, callback, timerId));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestRemoveMsgCallback, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    uint32_t messageSeq = 123;
    EXPECT_NO_THROW(baseSocket->RemoveMsgCallback(messageSeq));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestGetMsgCallback, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    uint32_t messageSeq = 123;
    EXPECT_NO_THROW(baseSocket->GetMsgCallback(messageSeq));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestPrintTransferDuration, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    uint32_t messageSeq = 123;
    EXPECT_NO_THROW(baseSocket->PrintTransferDuration(messageSeq));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestGetReplyTimer, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    uint32_t messageSeq = 123;
    EXPECT_NO_THROW(baseSocket->GetReplyTimer(messageSeq));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestStartReplyTimer, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    uint32_t messageSeq = 123;
    EXPECT_NO_THROW(baseSocket->StartReplyTimer(messageSeq));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestStopReplyTimer, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    uint32_t messageSeq = 123;
    EXPECT_NO_THROW(baseSocket->StopReplyTimer(messageSeq));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestReplyTimerTimeOut, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    uint32_t messageSeq = 123;
    EXPECT_NO_THROW(baseSocket->ReplyTimerTimeOut(messageSeq));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestSetDeviceNetworkId, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::string networkId = "456";
    std::shared_ptr<Attributes> attributes = Common::MakeShared<Attributes>();
    ASSERT_NE(attributes, nullptr);
    EXPECT_NO_THROW(baseSocket->SetDeviceNetworkId(networkId, attributes));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestSendRequest, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::string connectionName = "connectionName";
    std::string srcEndPoint = "123";
    std::string destEndPoint = "456";
    std::shared_ptr<Attributes> attributes = Common::MakeShared<Attributes>();
    ASSERT_NE(attributes, nullptr);
    attributes->SetInt32Value(Attributes::ATTR_MSG_TYPE, 1);
    MsgCallback callback;
    EXPECT_EQ(baseSocket->SendRequest(socketId, connectionName, srcEndPoint, destEndPoint, attributes,
        callback), GENERAL_ERROR);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestSendResponse, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::string connectionName = "connectionName";
    std::string srcEndPoint = "123";
    std::string destEndPoint = "456";
    std::shared_ptr<Attributes> attributes = Common::MakeShared<Attributes>();
    ASSERT_NE(attributes, nullptr);
    attributes->SetInt32Value(Attributes::ATTR_MSG_TYPE, 1);
    uint32_t messageSeq = 123;
    EXPECT_EQ(baseSocket->SendResponse(socketId, connectionName, srcEndPoint, destEndPoint, attributes,
        messageSeq), GENERAL_ERROR);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestParseMessage_001, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::string networkId = "networkId";
    void *message = nullptr;
    uint32_t messageLen = 0;
    std::shared_ptr<SoftBusMessage> result = baseSocket->ParseMessage(networkId, message, messageLen);
    ASSERT_EQ(result, nullptr);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestParseMessage_002, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::string networkId = "networkId";
    void *message = new char[10];
    uint32_t messageLen = 0;
    std::shared_ptr<SoftBusMessage> result = baseSocket->ParseMessage(networkId, message, messageLen);
    ASSERT_EQ(result, nullptr);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestParseMessage_003, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::string networkId = "networkId";
    void *message = new char[10];
    uint32_t messageLen = 10;
    std::shared_ptr<SoftBusMessage> result = baseSocket->ParseMessage(networkId, message, messageLen);
    ASSERT_EQ(result, nullptr);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestProcessMessage_001, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(0, "", "", "", nullptr);
    std::shared_ptr<Attributes> attributes = Common::MakeShared<Attributes>();
    ASSERT_NE(attributes, nullptr);
    EXPECT_NO_THROW(baseSocket->ProcessMessage(softBusMessage, attributes));
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestProcDataReceive_001, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::shared_ptr<SoftBusMessage> softBusMessage = nullptr;
    ResultCode result = baseSocket->ProcDataReceive(socketId, softBusMessage);
    ASSERT_EQ(result, INVALID_PARAMETERS);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestProcDataReceive_002, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(0, "", "", "", nullptr);
    ResultCode result = baseSocket->ProcDataReceive(socketId, softBusMessage);
    ASSERT_EQ(result, 2);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestProcDataReceive_003, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(0, "", "", "", nullptr);
    softBusMessage->isAck_ = true;
    ResultCode result = baseSocket->ProcDataReceive(socketId, softBusMessage);
    ASSERT_EQ(result, 2);
    delete baseSocket;
}


HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestProcDataReceive_004, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(0, "", "", "", nullptr);
    softBusMessage->isAck_ = true;
    softBusMessage->CreateMessage(true);
    ResultCode result = baseSocket->ProcDataReceive(socketId, softBusMessage);
    ASSERT_EQ(result, 2);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestProcDataReceive_005, TestSize.Level0)
{
    int32_t socketId = 1;
    BaseSocketTest *baseSocket = new BaseSocketTest(socketId);
    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(0, "", "", "", nullptr);
    softBusMessage->isAck_ = true;
    softBusMessage->CreateMessage(true);
    ResultCode result = baseSocket->ProcDataReceive(socketId, softBusMessage);
    ASSERT_EQ(result, 2);
    delete baseSocket;
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestParseMessage_004, TestSize.Level0)
{
    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(0, "", "", "", nullptr);
    void *message = new char[10];
    uint32_t messageLen = 0;
    std::shared_ptr<Attributes> attributes = softBusMessage->ParseMessage(message, messageLen);
    ASSERT_EQ(attributes, nullptr);
}

HWTEST_F(SoftBusBaseSocketTest, SoftBusBaseSocketTestParseMessage_005, TestSize.Level0)
{
    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(0, "", "", "", nullptr);
    void *message = new char[10];
    uint32_t messageLen = 10;
    std::shared_ptr<Attributes> attributes = softBusMessage->ParseMessage(message, messageLen);
    ASSERT_EQ(attributes, nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
