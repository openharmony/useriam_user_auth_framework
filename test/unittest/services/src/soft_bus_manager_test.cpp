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

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestSocketUnInit_001, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().ServiceSocketUnInit();
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestRegistSoftBusListener, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().RegistSoftBusListener();
        SoftBusManager::GetInstance().RegistSoftBusListener();
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestSocketInit, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().ServiceSocketInit();
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestSocketUnInit_002, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().ServiceSocketUnInit();
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestUnRegistSoftBusListener, TestSize.Level0)
{
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().UnRegistSoftBusListener();
        SoftBusManager::GetInstance().UnRegistSoftBusListener();
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestServiceSocketListen, TestSize.Level0)
{
    int32_t socketId = 100;
    SoftBusManager::GetInstance().RegistSoftBusListener();
    SoftBusManager::GetInstance().ServiceSocketInit();
    std::shared_ptr<BaseSocket> serverSocket = SocketFactory::CreateServerSocket(socketId);
    int ret = SoftBusManager::GetInstance().ServiceSocketListen(socketId);
    EXPECT_EQ(ret, LISTEN_SOCKET_FAILED);
    SoftBusManager::GetInstance().AddSocket(socketId, serverSocket);
    SoftBusManager::GetInstance().SetServerSocket(serverSocket);

    int32_t clientSocketId = 200;
    const std::string connectionName = "testConnection";
    const uint32_t tokenId = 1234;
    const std::string networkId = "networkId";
    SoftBusManager::GetInstance().DoOpenConnection(connectionName, tokenId, networkId);
    auto clientSocket = SocketFactory::CreateClientSocket(clientSocketId, connectionName, networkId);
    EXPECT_EQ(SoftBusManager::GetInstance().ClientSocketBind(clientSocketId), GENERAL_ERROR);
    SoftBusManager::GetInstance().AddConnection(connectionName, clientSocket);
    SoftBusManager::GetInstance().AddSocket(clientSocketId, clientSocket);
    RemoteConnectListenerManager::GetInstance().OnConnectionUp(connectionName);

    EXPECT_EQ(SoftBusManager::GetInstance().DoCloseConnection(connectionName), SUCCESS);
    SoftBusManager::GetInstance().ServiceSocketUnInit();
    SoftBusManager::GetInstance().UnRegistSoftBusListener();
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOpenConnection, TestSize.Level0)
{
    const std::string connectionName = "testConnection";
    const uint32_t tokenId = 1234;
    const std::string networkId = "networkId";
    SoftBusManager::GetInstance().DoOpenConnection(connectionName, tokenId, networkId);
    EXPECT_EQ(SoftBusManager::GetInstance().DoCloseConnection(connectionName), GENERAL_ERROR);
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnServerBytes_001, TestSize.Level0)
{
    int32_t socketId = 100;
    const void *data = new char[10];
    uint32_t dataLen = 3;
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnServerBytes_002, TestSize.Level0)
{
    int32_t socketId = 100;
    const void *data = new char[10];
    uint32_t dataLen = 3;
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().ClearServerSocket();
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    });
}

HWTEST_F(SoftBusManagerTest, SoftBusManagerTestOnServerBytes_003, TestSize.Level0)
{
    int32_t socketId = -2;
    const void *data = new char[10];
    uint32_t dataLen = 3;
    EXPECT_NO_THROW({
        SoftBusManager::GetInstance().ClearServerSocket();
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
        SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
    });
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
