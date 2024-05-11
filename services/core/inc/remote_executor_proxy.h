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

#ifndef REMOTE_EXECUTOR_PROXY_H
#define REMOTE_EXECUTOR_PROXY_H

#include <functional>

#include "attributes.h"
#include "co_auth_client_callback.h"
#include "co_auth_client_defines.h"
#include "executor_callback_interface.h"
#include "remote_connect_manager.h"
#include "remote_msg_util.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteExecutorProxy : public std::enable_shared_from_this<RemoteExecutorProxy> {
public:
    RemoteExecutorProxy(std::string connectionName, ExecutorInfo registerInfo);
    virtual ~RemoteExecutorProxy();

    ResultCode Start();

    // ConnectionListener
    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply);
    void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus);

    // ExecutorCallbackInterface
    void OnMessengerReady(uint64_t executorIndex, const std::shared_ptr<ExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList);
    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey, const Attributes &command);
    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &command);
    int32_t OnSendData(uint64_t scheduleId, const Attributes &data);

    void OnErrorFinish();

private:
    // ExecutorMessengerInterface
    int32_t ProcSendDataMsg(Attributes &data);
    int32_t ProcFinishMsg(Attributes &data);

    std::recursive_mutex mutex_;
    std::shared_ptr<ConnectionListener> connectionCallback_ = nullptr;
    std::shared_ptr<ExecutorRegisterCallback> executorCallback_ = nullptr;
    std::shared_ptr<ExecutorMessenger> messenger_ = nullptr;

    uint64_t executorIndex_ = 0;
    std::string connectionName_ = "";
    ExecutorInfo registerInfo_ = {};
    std::string endPointName_ = "";
    uint64_t scheduleId_ = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_EXECUTOR_PROXY_H