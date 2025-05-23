/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef REMOTE_EXECUTOR_STUB_H
#define REMOTE_EXECUTOR_STUB_H

#include <optional>

#include "attributes.h"
#include "co_auth_client_defines.h"
#include "iexecutor_callback.h"
#include "hisysevent_adapter.h"
#include "nocopyable.h"
#include "remote_connect_manager.h"
#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteExecutorStub : public std::enable_shared_from_this<RemoteExecutorStub> {
public:
public:
    RemoteExecutorStub();
    virtual ~RemoteExecutorStub();

    // ConnectionListener
    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply);

    // ScheduleNode
    int32_t OnMessage(ExecutorRole dstRole, const std::vector<uint8_t> &msg);
    int32_t ContinueSchedule(ResultCode resultCode, const std::shared_ptr<Attributes> &finalResult);

    // IExecutorCallback
    int32_t ProcBeginExecuteRequest(Attributes &attr, RemoteExecuteTrace &trace);

private:
    int32_t ProcSendDataMsg(Attributes &attr);

    std::recursive_mutex mutex_;
    std::shared_ptr<ConnectionListener> connectionCallback_ = nullptr;
    std::shared_ptr<ScheduleNode> remoteScheduleNode_ = nullptr;
    uint64_t executorIndex_ = 0;
    std::string connectionName_ = "";
    std::string endPointName_ = "";
    std::optional<uint64_t> contextId_ = std::nullopt;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_EXECUTOR_STUB_H