/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "soft_bus_client_socket.h"

#include "remote_connect_listener_manager.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
ClientSocket::ClientSocket(const int32_t socketId)
    : BaseSocket(socketId)
{
    IAM_LOGI("client socket id is %{public}d.", socketId);
}

ResultCode ClientSocket::SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    IAM_LOGI("start.");
    int32_t socketId = GetSocketId();
    if (socketId == INVALID_SOCKET_ID) {
        return GENERAL_ERROR;
    }

    return SendRequest(socketId, connectionName, srcEndPoint, destEndPoint, attributes, callback);
}

void ClientSocket::OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
}

void ClientSocket::OnShutdown(int32_t socketId, ShutdownReason reason)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
    std::string connectionName = GetConnectionName();
    if (!connectionName.empty()) {
        RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
    }
}

void ClientSocket::OnBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
    IF_FALSE_LOGE_AND_RETURN(data != nullptr);
    IF_FALSE_LOGE_AND_RETURN(dataLen != 0);

    std::string networkId = GetNetworkId();
    if (networkId.empty()) {
        IAM_LOGE("networkId id is null, socketId:%{public}d.", socketId);
        return;
    }

    std::shared_ptr<SoftBusMessage> softBusMessage = ParseMessage(networkId, const_cast<void *>(data), dataLen);
    if (softBusMessage == nullptr) {
        IAM_LOGE("serverSocket parse message fail.");
        return;
    }

    ResultCode ret = ProcDataReceive(socketId, softBusMessage);
    if (ret != SUCCESS) {
        IAM_LOGE("HandleDataReceive fail, socketId:%{public}d.", socketId);
        return;
    }
}

void ClientSocket::OnBind(int32_t socketId, PeerSocketInfo info)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
}

std::string ClientSocket::GetConnectionName()
{
    return connectionName_;
}

std::string ClientSocket::GetNetworkId()
{
    return networkId_;
}

void ClientSocket::SetConnectionName(const std::string &connectionName)
{
    connectionName_ = connectionName;
}

void ClientSocket::SetNetworkId(const std::string &networkId)
{
    networkId_ = networkId;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS