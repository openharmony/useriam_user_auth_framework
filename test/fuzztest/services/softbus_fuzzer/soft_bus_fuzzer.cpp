/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "soft_bus_fuzzer.h"

#include "parcel.h"

#include "soft_bus_base_socket.h"
#include "soft_bus_client_socket.h"
#include "soft_bus_manager.h"
#include "soft_bus_message.h"
#include "soft_bus_server_socket.h"
#include "soft_bus_socket_listener.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"

using namespace std;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

void FuzzSoftBusManagerSecond(SoftBusManager &softBusManager)
{
    IAM_LOGI("start");
    softBusManager.GetServerSocket();
    softBusManager.Stop();
    softBusManager.RegistDeviceManagerListener();
    softBusManager.UnRegistDeviceManagerListener();
    softBusManager.RegistSoftBusListener();
    softBusManager.UnRegistSoftBusListener();
    softBusManager.DeviceInit();
    softBusManager.DeviceUnInit();
    softBusManager.ServiceSocketInit();
    softBusManager.ServiceSocketUnInit();
    softBusManager.ClearServerSocket();
    IAM_LOGI("end");
}

void FuzzSoftBusBaseSocketFisrst(Parcel &parcel)
{
    IAM_LOGI("start");
    std::string connectionName = parcel.ReadString();
    int32_t socketId = parcel.ReadInt32();
    auto clientSocket = Common::MakeShared<ClientSocket>(socketId);
    clientSocket->GetSocketId();
    std::string srcEndPoint = parcel.ReadString();
    std::string destEndPoint = parcel.ReadString();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    auto attributes = Common::MakeShared<Attributes>(attr);
    MsgCallback callback = nullptr;
    clientSocket->SendMessage(connectionName, srcEndPoint, destEndPoint, attributes, callback);
    uint32_t messageSeq = parcel.ReadUint32();
    clientSocket->SendResponse(socketId, connectionName, srcEndPoint, destEndPoint, attributes, messageSeq);
    std::string networkId = parcel.ReadString();
    clientSocket->GetConnectionName();
    clientSocket->GetMsgCallback(messageSeq);
    uint32_t timerId = parcel.ReadUint32();
    clientSocket->InsertMsgCallback(messageSeq, connectionName, callback, timerId);
    clientSocket->RemoveMsgCallback(messageSeq);
    clientSocket->GetReplyTimer(messageSeq);
    clientSocket->StartReplyTimer(messageSeq);
    clientSocket->StopReplyTimer(messageSeq);
    clientSocket->ReplyTimerTimeOut(messageSeq);
    clientSocket->GetMessageSeq();
    clientSocket->SetDeviceNetworkId(networkId, attributes);
    clientSocket->PrintTransferDuration(messageSeq);
    IAM_LOGI("end");
}

void FuzzSoftBusServerSocketFisrst(Parcel &parcel)
{
    IAM_LOGI("start");
    int32_t socketId = parcel.ReadInt32();
    auto serverSocket = Common::MakeShared<ServerSocket>(socketId);
    std::string connectionName = parcel.ReadString();
    ShutdownReason reason = SHUTDOWN_REASON_LOCAL;
    serverSocket->OnShutdown(socketId, reason);
    serverSocket->GetConnectionName();
    std::string networkId = parcel.ReadString();
    serverSocket->GetNetworkId();
    serverSocket->AddServerSocket(socketId, networkId);
    serverSocket->DeleteServerSocket(socketId);
    serverSocket->AddClientConnection(socketId, connectionName);
    serverSocket->DeleteClientConnection(socketId);
    serverSocket->GetNetworkIdBySocketId(socketId);
    serverSocket->GetClientConnectionName(socketId);
    serverSocket->GetSocketIdByClientConnectionName(connectionName);
    IAM_LOGI("end");
}

void FuzzSoftBusManagerFisrst(Parcel &parcel)
{
    IAM_LOGI("start");
    SoftBusManager softBusManager;
    softBusManager.Start();
    uint32_t tokenId = parcel.ReadUint32();
    std::string networkId = parcel.ReadString();
    std::string connectionName = parcel.ReadString();
    softBusManager.OpenConnection(connectionName, tokenId, networkId);
    std::string srcEndPoint = parcel.ReadString();
    std::string destEndPoint = parcel.ReadString();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    auto attributes = Common::MakeShared<Attributes>(attr);
    MsgCallback callback = nullptr;
    softBusManager.SendMessage(connectionName, srcEndPoint, destEndPoint, attributes, callback);
    std::shared_ptr<BaseSocket> clientSocket = softBusManager.FindClientSocket(connectionName);
    int32_t socketId = parcel.ReadInt32();
    PeerSocketInfo info;
    softBusManager.OnBind(socketId, info);
    ShutdownReason reason = SHUTDOWN_REASON_LOCAL;
    softBusManager.OnShutdown(socketId, reason);
    softBusManager.OnClientBytes(socketId, nullptr, 0);
    softBusManager.OnServerBytes(socketId, nullptr, 0);
    softBusManager.DoOpenConnection(connectionName, tokenId, networkId);
    FuzzSoftBusManagerSecond(softBusManager);
    softBusManager.CloseConnection(connectionName);
    softBusManager.ServiceSocketListen(socketId);
    softBusManager.ClientSocketBind(socketId);
    std::string src = parcel.ReadString();
    softBusManager.CheckAndCopyStr(nullptr, 0, src);
    softBusManager.AddConnection(connectionName, clientSocket);
    softBusManager.DeleteConnection(connectionName);
    softBusManager.AddSocket(socketId, clientSocket);
    softBusManager.DeleteSocket(socketId);
    softBusManager.SetServerSocket(clientSocket);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzSoftBusManagerFisrst);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzSoftBusManagerFisrst,
    FuzzSoftBusBaseSocketFisrst,
    FuzzSoftBusServerSocketFisrst,
};

void SoftBusFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}

} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::UserIam::UserAuth::SoftBusFuzzTest(data, size);
    return 0;
}
