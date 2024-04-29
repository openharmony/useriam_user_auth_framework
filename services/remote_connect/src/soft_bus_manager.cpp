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

#include "soft_bus_manager.h"

#include <string>
#include <thread>
#include "socket.h"

#include "device_state_listener.h"
#include "device_manager.h"
#include "iam_logger.h"
#include "iservice_registry.h"
#include "socket_factory.h"
#include "soft_bus_base_socket.h"
#include "soft_bus_socket_listener.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::DistributedHardware;
static const std::string USER_AUTH_PACKAGE_NAME = "ohos.useriam";
static const std::string USER_AUTH_SOCKET_NAME = "ohos.useriam.";
static constexpr uint32_t SOCKET_NAME_MAX_LEN = 256;
static constexpr uint32_t PACKAGE_NAME_MAX_LEN = 256;

static constexpr uint32_t QOS_LEN = 3;
static constexpr int32_t MIN_BW = 1024 * 1024; // 1M
static constexpr int32_t MAX_LATENCY = 30 * 1000; // 30s
static constexpr int32_t MIN_LATENCY = 100; // 100ms
static constexpr int32_t MAX_TIMEOUT = 3 * 60 * 1000; // 3min

static constexpr int32_t BIND_SERVICE_MAX_RETRY_TIMES = 10;
static constexpr int32_t BIND_SERVICE_SLEEP_TIMES_MS = 100; // 0.1s

static const int32_t MAX_ONBYTES_RECEIVED_DATA_LEN = 1024 * 1024 * 10;

SoftBusManager::SoftBusManager()
{
    IAM_LOGI("start.");
}

SoftBusManager::~SoftBusManager()
{
    IAM_LOGI("start.");
}

SoftBusManager &SoftBusManager::GetInstance()
{
    IAM_LOGI("start.");
    static SoftBusManager instance;
    return instance;
}

void SoftBusManager::Start()
{
    IAM_LOGI("start.");
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    if (inited_ == true) {
        IAM_LOGI("already initialized, skip");
        return;
    }
    ResultCode ret = RegistDeviceManagerListener();
    if (ret != SUCCESS) {
        IAM_LOGI("RegistDeviceManagerListener fail");
        return;
    }
    ret = RegistSoftBusListener();
    if (ret != SUCCESS) {
        IAM_LOGI("RegistSoftBusListener fail");
        return;
    }
    inited_ = true;
}

void SoftBusManager::Stop()
{
    IAM_LOGI("start.");
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    if (inited_ == false) {
        IAM_LOGI("not inited, skip");
        return;
    }
    ResultCode ret = UnRegistDeviceManagerListener();
    if (ret != SUCCESS) {
        IAM_LOGI("UnRegistDeviceManagerListener fail");
        return;
    }
    ret = UnRegistSoftBusListener();
    if (ret != SUCCESS) {
        IAM_LOGI("UnRegistSoftBusListener fail");
        return;
    }
    inited_ = false;
}

ResultCode SoftBusManager::RegistDeviceManagerListener()
{
    IAM_LOGI("start.");
    if (deviceManagerServiceListener_ != nullptr) {
        IAM_LOGI("deviceManagerServiceListener_ is not nullptr.");
        return SUCCESS;
    }

    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("sam is nullptr.");
        return GENERAL_ERROR;
    }

    sptr<DeviceManagerListener> deviceManagerListener(
        new (std::nothrow) DeviceManagerListener("device_manager",
        DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        []() {
            SoftBusManager::GetInstance().DeviceInit();
        },
        []() {
            SoftBusManager::GetInstance().DeviceUnInit();
        }));
    if (deviceManagerListener == nullptr) {
        IAM_LOGE("listener is nullptr.");
        return GENERAL_ERROR;
    }

    int32_t ret = sam->SubscribeSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID, deviceManagerListener);
    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeSystemAbility fail.");
        return GENERAL_ERROR;
    }

    deviceManagerServiceListener_ = deviceManagerListener;
    IAM_LOGE("RegistDeviceManagerListener success.");
    return SUCCESS;
}

ResultCode SoftBusManager::UnRegistDeviceManagerListener()
{
    IAM_LOGI("start.");
    if (deviceManagerServiceListener_ == nullptr) {
        IAM_LOGI("deviceManagerServiceListener_ is nullptr.");
        return SUCCESS;
    }

    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("sam is nullptr.");
        return GENERAL_ERROR;
    }

    int32_t ret = sam->UnSubscribeSystemAbility(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        deviceManagerServiceListener_);
    if (ret != SUCCESS) {
        IAM_LOGE("UnSubscribeSystemAbility fail.");
        return GENERAL_ERROR;
    }

    deviceManagerServiceListener_ = nullptr;
    IAM_LOGE("UnRegistDeviceManagerListener success.");
    return SUCCESS;
}

ResultCode SoftBusManager::RegistSoftBusListener()
{
    IAM_LOGI("start.");
    if (softBusServiceListener_ != nullptr) {
        IAM_LOGI("softBusServiceListener_ is not nullptr.");
        return SUCCESS;
    }

    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("sam is nullptr.");
        return GENERAL_ERROR;
    }

    sptr<SoftBusListener> softBusListener(
        new (std::nothrow) SoftBusListener("softbus_server",
        SOFTBUS_SERVER_SA_ID,
        []() {
            SoftBusManager::GetInstance().ServiceSocketInit();
        },
        []() {
            SoftBusManager::GetInstance().ServiceSocketUnInit();
        }));
    if (softBusListener == nullptr) {
        IAM_LOGE("listener is nullptr.");
        return GENERAL_ERROR;
    }

    int32_t ret = sam->SubscribeSystemAbility(SOFTBUS_SERVER_SA_ID, softBusListener);
    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeSystemAbility fail.");
        return GENERAL_ERROR;
    }

    softBusServiceListener_ = softBusListener;
    IAM_LOGE("RegistDeviceManagerListener success.");
    return SUCCESS;
}

ResultCode SoftBusManager::UnRegistSoftBusListener()
{
    IAM_LOGI("start.");
    if (softBusServiceListener_ == nullptr) {
        IAM_LOGI("softBusServiceListener_ is nullptr.");
        return SUCCESS;
    }

    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("sam is nullptr.");
        return GENERAL_ERROR;
    }

    int32_t ret = sam->UnSubscribeSystemAbility(SOFTBUS_SERVER_SA_ID, softBusServiceListener_);
    if (ret != SUCCESS) {
        IAM_LOGE("UnSubscribeSystemAbility fail.");
        return GENERAL_ERROR;
    }

    softBusServiceListener_ = nullptr;
    IAM_LOGE("UnRegistDeviceManagerListener success.");
    return SUCCESS;
}

ResultCode SoftBusManager::DeviceInit()
{
    IAM_LOGI("start.");
    auto dmInitCallback = Common::MakeShared<IamDmInitCallback>();
    if (dmInitCallback == nullptr) {
        IAM_LOGE("dmInitCallback create fail");
        return GENERAL_ERROR;
    }

    int ret = DeviceManager::GetInstance().InitDeviceManager(USER_AUTH_PACKAGE_NAME, dmInitCallback);
    if (ret != SUCCESS) {
        IAM_LOGE("Initialize: InitDeviceManager error, result: %{public}d", ret);
        return GENERAL_ERROR;
    }

    DmDeviceInfo deviceInfo;
    ret = DeviceManager::GetInstance().GetLocalDeviceInfo(USER_AUTH_PACKAGE_NAME, deviceInfo);
    std::string networkId = deviceInfo.networkId;
    IAM_LOGI("networkId : %{public}s", networkId.c_str());
    std::string deviceId = deviceInfo.deviceId;
    IAM_LOGI("deviceId : %{public}s", deviceId.c_str());

    return SUCCESS;
}

void SoftBusManager::DeviceUnInit()
{
    IAM_LOGI("start.");
    int32_t ret = DeviceManager::GetInstance().UnInitDeviceManager(USER_AUTH_PACKAGE_NAME);
    if (ret != SUCCESS) {
        IAM_LOGE("UnInitDeviceManager failed, code: %{public}d", ret);
    }

    IAM_LOGI("DeviceUnInit success");
}

ResultCode SoftBusManager::ServiceSocketListen()
{
    IAM_LOGI("start.");
    QosTV serverQos[] = {
        { .qos = QOS_TYPE_MIN_BW,      .value = MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = MIN_LATENCY },
        { .qos = QOS_TYPE_MAX_WAIT_TIMEOUT, .value = MAX_TIMEOUT },
    };

    ISocketListener listener;
    listener.OnBind = SoftBusSocketListener::OnBind;
    listener.OnShutdown = SoftBusSocketListener::OnShutdown;
    listener.OnBytes = SoftBusSocketListener::OnClientBytes;

    int32_t ret = Listen(socketId_, serverQos, QOS_LEN, &listener);
    if (ret != SUCCESS) {
        IAM_LOGE("create listener failed, ret is %{public}d.", ret);
        return LISTEN_SOCKET_FAILED;
    }

    IAM_LOGI("ServiceSocketListen success.");
    return SUCCESS;
}

ResultCode SoftBusManager::ServiceSocketInit()
{
    IAM_LOGI("start.");
    std::string serviceName = USER_AUTH_SOCKET_NAME + "service";
    char name[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(name, SOCKET_NAME_MAX_LEN, serviceName)) {
        IAM_LOGE("copy socket name fail");
        return GENERAL_ERROR;
    }

    char pkgName[PACKAGE_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(pkgName, PACKAGE_NAME_MAX_LEN, USER_AUTH_PACKAGE_NAME)) {
        IAM_LOGE("copy pkg name fail");
        return GENERAL_ERROR;
    }

    SocketInfo info = {
        .name = name,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };
    int32_t socketId = Socket(info);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("create service socket faild.");
        return CREATE_SOCKET_FAILED;
    }

    socketId_ = socketId;
    int ret = ServiceSocketListen();
    if (ret != SUCCESS) {
        IAM_LOGE("socket listen faild, ret is %{public}d.", ret);
        return LISTEN_SOCKET_FAILED;
    }

    auto serverSocket = SocketFactory::CreateServerSocket(socketId);
    if (serverSocket == nullptr) {
        IAM_LOGE("server socket create faild.");
        return GENERAL_ERROR;
    }

    AddSocket(socketId, serverSocket);
    serverSocket_ = serverSocket;
    IAM_LOGI("ServiceSocketInit success.");
    return SUCCESS;
}

void SoftBusManager::ServiceSocketUnInit()
{
    IAM_LOGI("start.");
    DeleteSocket(socketId_);
    serverSocket_ = nullptr;
    IAM_LOGI("UnInitialize success");
}

int32_t SoftBusManager::ClientSocketInit(const std::string &connectionName, const std::string& networkId)
{
    IAM_LOGI("start.");
    std::string clientName = USER_AUTH_SOCKET_NAME + connectionName;
    char name[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(name, SOCKET_NAME_MAX_LEN, clientName)) {
        IAM_LOGE("copy socket name fail");
        return INVALID_SOCKET_ID;
    }

    std::string serviceName = USER_AUTH_SOCKET_NAME + "service";
    char peerName[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(peerName, SOCKET_NAME_MAX_LEN, serviceName)) {
        IAM_LOGE("copy peer name fail");
        return INVALID_SOCKET_ID;
    }

    char peerNetworkId[SOCKET_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(peerNetworkId, SOCKET_NAME_MAX_LEN, networkId)) {
        IAM_LOGE("copy peer networkId name fail");
        return INVALID_SOCKET_ID;
    }

    char pkgName[PACKAGE_NAME_MAX_LEN + 1];
    if (!CheckAndCopyStr(pkgName, PACKAGE_NAME_MAX_LEN, USER_AUTH_PACKAGE_NAME)) {
        IAM_LOGE("copy pkg name fail");
        return INVALID_SOCKET_ID;
    }

    SocketInfo info = {
        .name = name,
        .peerName = peerName,
        .peerNetworkId = peerNetworkId,
        .pkgName = pkgName,
        .dataType = DATA_TYPE_BYTES
    };

    return Socket(info);
}

ResultCode SoftBusManager::ClientSocketBind(const int32_t socketId)
{
    IAM_LOGI("start.");
    QosTV clientQos[] = {
        { .qos = QOS_TYPE_MIN_BW,      .value = MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = MIN_LATENCY },
    };

    ISocketListener listener;
    listener.OnShutdown = SoftBusSocketListener::OnShutdown;
    listener.OnBytes = SoftBusSocketListener::OnServerBytes;
    listener.OnQos = SoftBusSocketListener::OnQos;

    int32_t ret = SUCCESS;
    int32_t retryTimes = 0;
    auto sleepTime = std::chrono::milliseconds(BIND_SERVICE_SLEEP_TIMES_MS);
    while (retryTimes < BIND_SERVICE_MAX_RETRY_TIMES) {
        ret = Bind(socketId, clientQos, QOS_LEN, &listener);
        if (ret != SUCCESS) {
            std::this_thread::sleep_for(sleepTime);
            retryTimes++;
            continue;
        }
        break;
    }

    if (ret != SUCCESS) {
        IAM_LOGE("ClientSocketBind fail.");
        return GENERAL_ERROR;
    }
    IAM_LOGI("ClientSocketBind success.");
    return SUCCESS;
}

ResultCode SoftBusManager::OpenConnection(const std::string &connectionName, const uint32_t tokenId,
    const std::string &networkId)
{
    IAM_LOGI("start.");
    int32_t ret = SetFirstCallerTokenID(tokenId);
    if (ret != SUCCESS) {
        IAM_LOGI("SetFirstCallerTokenID fail");
    }
    int32_t socketId = ClientSocketInit(connectionName, networkId);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("create client socket faild.");
        return GENERAL_ERROR;
    }

    auto clientSocket = SocketFactory::CreateClientSocket(socketId, connectionName, networkId);
    if (clientSocket == nullptr) {
        IAM_LOGE("CreateClientSocket failed, connectionName:%{public}s", connectionName.c_str());
        return GENERAL_ERROR;
    }

    ret = ClientSocketBind(socketId);
    if (ret != SUCCESS) {
        IAM_LOGE("client socket bind service success");
        return GENERAL_ERROR;
    }

    AddConnection(connectionName, clientSocket);
    AddSocket(socketId, clientSocket);
    IAM_LOGI("Bind service succeed, socketId is %{public}d.", socketId);
    return SUCCESS;
}

ResultCode SoftBusManager::CloseConnection(const std::string &connectionName)
{
    IAM_LOGI("start.");
    std::shared_ptr<BaseSocket> clientSocket = FindClientSocket(connectionName);
    if (clientSocket == nullptr) {
        IAM_LOGE("clientSocket is nullptr");
        return GENERAL_ERROR;
    }

    int32_t socketId = clientSocket->GetSocketId();
    if (socketId == INVALID_SOCKET_ID) {
        IAM_LOGE("socket id is invalid");
        return GENERAL_ERROR;
    }

    Shutdown(socketId);
    DeleteConnection(connectionName);
    IAM_LOGI("close socket success");
    return SUCCESS;
}

ResultCode SoftBusManager::SendMessage(const std::string &connectionName,
    const std::string &srcEndPoint, const std::string &destEndPoint,
    const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    IAM_LOGI("start.");
    ResultCode ret = SUCCESS;
    auto serverSocket = GetServerSocket();
    if (serverSocket != nullptr) {
        ret = serverSocket->SendMessage(connectionName, srcEndPoint, destEndPoint, attributes, callback);
        if (ret != SUCCESS) {
            IAM_LOGI("serverSocket send message fail, ret:%{public}d", ret);
        }
    }

    std::shared_ptr<BaseSocket> clientSocket = FindClientSocket(connectionName);
    if (clientSocket != nullptr) {
        ret = clientSocket->SendMessage(connectionName, srcEndPoint, destEndPoint, attributes, callback);
        if (ret != SUCCESS) {
            IAM_LOGI("clientSocket send message fail, ret:%{public}d", ret);
        }
    }

    IAM_LOGI("SendMessage success.");
    return SUCCESS;
}

void SoftBusManager::OnBind(int32_t socketId, PeerSocketInfo info)
{
    IAM_LOGI("socket id is %{public}d.", socketId);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }

    auto serverSocket = GetServerSocket();
    if (serverSocket == nullptr) {
        IAM_LOGE("serverSocket is nullptr.");
        return;
    }
    
    serverSocket->OnBind(socketId, info);
}

void SoftBusManager::OnShutdown(int32_t socketId, ShutdownReason reason)
{
    IAM_LOGI("socket id %{public}d shutdown because %{public}u.", socketId, reason);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }

    auto serverSocket = GetServerSocket();
    if (serverSocket != nullptr) {
        serverSocket->OnShutdown(socketId, reason);
    }

    auto clientSocket = FindSocketBySocketId(socketId);
    if (clientSocket != nullptr) {
        IAM_LOGI("clientSocket is nullptr.");
        return;
    }
    clientSocket->OnShutdown(socketId, reason);
    DeleteSocket(socketId);
    DeleteConnection(clientSocket->GetConnectionName());
}

void SoftBusManager::OnClientBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("socket fd %{public}d, recv len %{public}d.", socketId, dataLen);
    if ((socketId <= INVALID_SOCKET_ID) || (data == nullptr) ||
        (dataLen == 0) || (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN)) {
        IAM_LOGE("params invalid.");
        return;
    }

    auto serverSocket = GetServerSocket();
    if (serverSocket == nullptr) {
        IAM_LOGE("serverSocket is nullptr.");
        return;
    }

    serverSocket->OnBytes(socketId, data, dataLen);
}

void SoftBusManager::OnServerBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("socket fd %{public}d, recv len %{public}d.", socketId, dataLen);
    if ((socketId <= INVALID_SOCKET_ID) || (data == nullptr) ||
        (dataLen == 0) || (dataLen > MAX_ONBYTES_RECEIVED_DATA_LEN)) {
        IAM_LOGE("params invalid.");
        return;
    }

    auto clientSocket = FindSocketBySocketId(socketId);
    if (clientSocket == nullptr) {
        IAM_LOGE("clientSocket is nullptr.");
        return;
    }

    clientSocket->OnBytes(socketId, data, dataLen);
}

void SoftBusManager::AddSocket(const int32_t socketId, std::shared_ptr<BaseSocket> &socket)
{
    IAM_LOGI("start.");
    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    socketMap_.insert(std::pair<int32_t, std::shared_ptr<BaseSocket>>(socketId, socket));
}

void SoftBusManager::DeleteSocket(const int32_t socketId)
{
    IAM_LOGI("start.");
    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    socketMap_.erase(socketId);
}

std::shared_ptr<BaseSocket> SoftBusManager::FindSocketBySocketId(const int32_t socketId)
{
    IAM_LOGI("start.");
    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    std::shared_ptr<BaseSocket> socket = nullptr;
    auto iter = socketMap_.find(socketId);
    if (iter != socketMap_.end()) {
        socket = iter->second;
    }
    return socket;
}

bool SoftBusManager::CheckAndCopyStr(char* dest, uint32_t destLen, const std::string& src)
{
    IAM_LOGI("start.");
    if (destLen < src.length() + 1) {
        IAM_LOGE("Invalid src length");
        return false;
    }
    if (strcpy_s(dest, destLen, src.c_str()) != EOK) {
        IAM_LOGE("Invalid src");
        return false;
    }
    return true;
}

void SoftBusManager::AddConnection(const std::string &connectionName, std::shared_ptr<BaseSocket> &socket)
{
    IAM_LOGI("start.");
    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    clientSocketMap_.insert(std::pair<std::string, std::shared_ptr<BaseSocket>>(connectionName, socket));
}

void SoftBusManager::DeleteConnection(const std::string &connectionName)
{
    IAM_LOGI("start.");
    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    clientSocketMap_.erase(connectionName);
}

std::shared_ptr<BaseSocket> SoftBusManager::FindClientSocket(const std::string &connectionName)
{
    IAM_LOGI("start.");
    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    std::shared_ptr<BaseSocket> clientSocket = nullptr;
    auto iter = clientSocketMap_.find(connectionName);
    if (iter != clientSocketMap_.end()) {
        clientSocket = iter->second;
    }
    return clientSocket;
}

std::shared_ptr<BaseSocket> SoftBusManager::GetServerSocket()
{
    return serverSocket_;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS