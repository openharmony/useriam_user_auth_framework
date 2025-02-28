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

#include "soft_bus_client_socket_test.h"
#include "soft_bus_client_socket.h"
#include "soft_bus_manager.h"
#include "remote_connect_listener_manager.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SoftBusClientSocketTest::SetUpTestCase()
{
}

void SoftBusClientSocketTest::TearDownTestCase()
{
}

void SoftBusClientSocketTest::SetUp()
{
}

void SoftBusClientSocketTest::TearDown()
{
}

class ClientSocketTest : public ClientSocket {
public:
    explicit ClientSocketTest(const int32_t socketId);
    ~ClientSocketTest();
};

ClientSocketTest::ClientSocketTest(const int32_t socketId)
    : ClientSocket(socketId)
{
}

ClientSocketTest::~ClientSocketTest()
{
}

HWTEST_F(SoftBusClientSocketTest, SoftBusClientSocketTestSendMessageSocketIdInvalid, TestSize.Level0)
{
    int32_t socketId = -1;
    ClientSocketTest *clientSocket = new ClientSocketTest(socketId);
    const std::string connectionName = "connectionName";
    const std::string srcEndPoint = "srcEndPoint";
    const std::string destEndPoint = "destEndPoint";
    MsgCallback msgCallback;
    EXPECT_EQ(clientSocket->SendMessage(connectionName, srcEndPoint, destEndPoint, nullptr, msgCallback),
        GENERAL_ERROR);
    delete clientSocket;
}

HWTEST_F(SoftBusClientSocketTest, SoftBusClientSocketTestOnBytesNetworkIdEmpty, TestSize.Level0)
{
    int32_t socketId = 1;
    ClientSocketTest *clientSocket = new ClientSocketTest(socketId);
    void *data = new char[10];
    uint32_t dataLen = 10;
    EXPECT_NO_THROW(clientSocket->OnBytes(socketId, data, dataLen));
    delete clientSocket;
}

HWTEST_F(SoftBusClientSocketTest, SoftBusClientSocketTestOnBytesSoftBusMessageNull, TestSize.Level0)
{
    int32_t socketId = 1;
    ClientSocketTest *clientSocket = new ClientSocketTest(socketId);
    const std::string networkId = "connectionName";
    clientSocket->SetNetworkId(networkId);
    void *data = new char[10];
    uint32_t dataLen = 10;
    EXPECT_NO_THROW(clientSocket->OnBytes(socketId, data, dataLen));
    delete clientSocket;
}

HWTEST_F(SoftBusClientSocketTest, SoftBusClientSocketTestRefreshKeepAliveTimerHasValue, TestSize.Level0)
{
    int32_t socketId = 1;
    ClientSocketTest *clientSocket = new ClientSocketTest(socketId);
    EXPECT_NO_THROW(clientSocket->RefreshKeepAliveTimer());
    EXPECT_NO_THROW(clientSocket->RefreshKeepAliveTimer());
    delete clientSocket;
}

HWTEST_F(SoftBusClientSocketTest, SoftBusClientSocketTestSendKeepAliveMessage, TestSize.Level0)
{
    int32_t socketId = 1;
    ClientSocketTest *clientSocket = new ClientSocketTest(socketId);
    EXPECT_NO_THROW(clientSocket->SendKeepAliveMessage());
    delete clientSocket;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
