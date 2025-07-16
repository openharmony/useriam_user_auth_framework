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

#include "soft_bus_manager_test.h"
#include "soft_bus_manager.h"
#include "socket_factory.h"
#include "socket.h"
#include "remote_connect_listener_manager.h"

#include "gtest/gtest.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void SoftBusManagerTest::SetUpTestCase()
{
}

void SoftBusManagerTest::TearDownTestCase()
{
}

void SoftBusManagerTest::SetUp()
{
}

void SoftBusManagerTest::TearDown()
{
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestCheckAndCopyStr, TestSize.Level0)
{
    char dest[1];
    uint32_t destLen = 2;
    const std::string src = "123123123";
    EXPECT_EQ(SoftBusManager::GetInstance().CheckAndCopyStr(dest, destLen, src), false);
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnBind_001, TestSize.Level0)
{
    PeerSocketInfo info;
    EXPECT_NO_THROW(SoftBusManager::GetInstance().OnBind(-2, info));
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestRegistSoftBusListener, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().RegistSoftBusListener();
        SoftBusManager::GetInstance().UnRegistSoftBusListener();
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestSocketInit, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().ServiceSocketInit();
        SoftBusManager::GetInstance().ServiceSocketUnInit();
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestDeleteSocket, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().DeleteSocket(600);
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestServiceSocketListen, TestSize.Level0)
{
    int32_t socketId = 100;
    SoftBusManager::GetInstance().ServiceSocketUnInit();
    SoftBusManager::GetInstance().ServiceSocketInit();
    int ret = SoftBusManager::GetInstance().ServiceSocketListen(socketId);
    EXPECT_EQ(ret, SUCCESS);

    PeerSocketInfo info;
    char testNetworkId[] = "1122";
    info.networkId = testNetworkId;
    EXPECT_NO_THROW(SoftBusManager::GetInstance().OnBind(socketId, info));

    int32_t clientSocketId = 200;
    const std::string connectionName = "testConnection";
    const uint32_t tokenId = 1234;
    const std::string networkId = "networkId";
    SoftBusManager::GetInstance().DoOpenConnection(connectionName, tokenId, networkId);
    auto clientSocket = SocketFactory::CreateClientSocket(clientSocketId, connectionName, networkId);
    EXPECT_EQ(SoftBusManager::GetInstance().ClientSocketBind(clientSocketId), SUCCESS);
    SoftBusManager::GetInstance().AddConnection(connectionName, clientSocket);
    SoftBusManager::GetInstance().AddSocket(clientSocketId, clientSocket);
    RemoteConnectListenerManager::GetInstance().OnConnectionUp(connectionName);

    const std::string srcEndPoint = "123";
    const std::string destEndPoint = "456";
    const std::shared_ptr<Attributes> attributes = Common::MakeShared<Attributes>();
    ASSERT_NE(attributes, nullptr);
    MsgCallback callback;
    EXPECT_EQ(SoftBusManager::GetInstance().SendMessage(connectionName, srcEndPoint, destEndPoint, attributes,
        callback), SUCCESS);

    EXPECT_EQ(SoftBusManager::GetInstance().DoCloseConnection(connectionName), SUCCESS);
    SoftBusManager::GetInstance().ServiceSocketUnInit();
    SoftBusManager::GetInstance().DeleteSocket(socketId);
    SoftBusManager::GetInstance().DeleteSocket(clientSocketId);
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOpenConnection, TestSize.Level0)
{
    const std::string connectionName = "testConnection";
    const uint32_t tokenId = 1234;
    const std::string networkId = "networkId";
    SoftBusManager::GetInstance().DoOpenConnection(connectionName, tokenId, networkId);
    EXPECT_EQ(SoftBusManager::GetInstance().DoCloseConnection(connectionName), SUCCESS);
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestServiceSocketUnInit_003, TestSize.Level0)
{
    int32_t socketId = 100;
    int32_t clientSocketId = 200;
    const std::string connectionName = "testConnection";
    const std::string networkId = "networkId";
    SoftBusManager::GetInstance().ServiceSocketUnInit();
    SoftBusManager::GetInstance().ServiceSocketInit();
    std::shared_ptr<BaseSocket> clientSocket = SocketFactory::CreateClientSocket(clientSocketId,
        connectionName, networkId);
    SoftBusManager::GetInstance().AddSocket(clientSocketId, clientSocket);
    auto findSocket = SoftBusManager::GetInstance().FindSocketBySocketId(socketId);
    EXPECT_EQ(findSocket, nullptr);
    SoftBusManager::GetInstance().ServiceSocketUnInit();
    SoftBusManager::GetInstance().DeleteSocket(socketId);
    SoftBusManager::GetInstance().DeleteSocket(clientSocketId);
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnServerBytes_001, TestSize.Level0)
{
    const void *data = new char[10];
    uint32_t dataLen = 3;
    int32_t socketId = 100;
    int32_t clientSocketId = 200;
    const std::string connectionName = "testConnection";
    const std::string networkId = "networkId";
    SoftBusManager::GetInstance().ServiceSocketUnInit();
    SoftBusManager::GetInstance().ServiceSocketInit();
    std::shared_ptr<BaseSocket> clientSocket = SocketFactory::CreateClientSocket(clientSocketId,
        connectionName, networkId);
    SoftBusManager::GetInstance().AddSocket(clientSocketId, clientSocket);
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    });
    SoftBusManager::GetInstance().ServiceSocketUnInit();
    SoftBusManager::GetInstance().DeleteSocket(socketId);
    SoftBusManager::GetInstance().DeleteSocket(clientSocketId);
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnShutdown_001, TestSize.Level0)
{
    ShutdownReason reason = SHUTDOWN_REASON_UNKNOWN;
    EXPECT_NO_THROW(SoftBusManager::GetInstance().OnShutdown(-2, reason));
    int32_t socketId = 100;
    std::shared_ptr<BaseSocket> serverSocket = SocketFactory::CreateServerSocket(socketId);
    SoftBusManager::GetInstance().AddSocket(socketId, serverSocket);
    SoftBusManager::GetInstance().SetServerSocket(serverSocket);
    EXPECT_NO_THROW(SoftBusManager::GetInstance().OnShutdown(600, reason));
    SoftBusManager::GetInstance().DeleteSocket(socketId);
    SoftBusManager::GetInstance().ServiceSocketUnInit();
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnServerBytes_002, TestSize.Level0)
{
    int32_t socketId = 100;
    const void *data = new char[10];
    uint32_t dataLen = 3;
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnServerBytes_003, TestSize.Level0)
{
    int32_t socketId = -2;
    const void *data = new char[10];
    uint32_t dataLen = 3;
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
        SoftBusManager::GetInstance().OnClientBytes(socketId, nullptr, dataLen);
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnClientBytes_001, TestSize.Level0)
{
    int32_t socketId = -2;
    const void *data = new char[10];
    uint32_t dataLen = 3;
    static const int32_t MAX_ONBYTES_RECEIVED_DATA_LEN = 1024 * 1024 * 10;
    std::string connectionName = "testConnection1";
    const std::string networkId = "networkId1";
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().OnClientBytes(socketId, data, dataLen);
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    });
    socketId = 0;
    SoftBusManager::GetInstance().OnClientBytes(socketId, data, dataLen);
    SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    socketId = 100;
    SoftBusManager::GetInstance().OnClientBytes(socketId, data, dataLen);
    SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    dataLen = 0;
    SoftBusManager::GetInstance().OnClientBytes(socketId, data, dataLen);
    SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    dataLen = MAX_ONBYTES_RECEIVED_DATA_LEN + 1;
    SoftBusManager::GetInstance().OnClientBytes(socketId, data, dataLen);
    SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    dataLen = 3;
    SoftBusManager::GetInstance().OnClientBytes(socketId, data, dataLen);
    SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    while (connectionName.length() <= 257) {
        connectionName += "testConnection1";
    }
    SoftBusManager::GetInstance().ClientSocketInit(connectionName, networkId);
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestStart, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().Start();
        SoftBusManager::GetInstance().Stop();
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestDeviceInit, TestSize.Level0)
{
    ResultCode ret = SoftBusManager::GetInstance().DeviceInit();
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NO_THROW(SoftBusManager::GetInstance().DeviceUnInit());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
