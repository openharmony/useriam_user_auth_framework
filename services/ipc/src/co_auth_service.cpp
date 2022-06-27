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

#include "co_auth_service.h"

#include <cinttypes>
#include <thread>

#include "executor_messenger_service.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "parameter.h"
#include "resource_node_pool.h"
#include "result_code.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void SendBootEvent()
{
    IAM_LOGI("SendBootEvent start");
    SetParameter("bootevent.useriam.fwkready", "true");
}

REGISTER_SYSTEM_ABILITY_BY_ID(CoAuthService, SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR, true);
CoAuthService::CoAuthService(int32_t systemAbilityId, bool runOnCreate) : SystemAbility(systemAbilityId, runOnCreate)
{
    IAM_LOGI("CoAuthService init");
}

void CoAuthService::OnStart()
{
    if (state_ == CoAuthRunningState::STATE_RUNNING) {
        IAM_LOGW("CoAuthService has already started");
        return;
    }
    IAM_LOGI("Start service");
    if (!Publish(this)) {
        IAM_LOGE("Failed to publish service");
        return;
    }
    state_ = CoAuthRunningState::STATE_RUNNING;
    std::thread checkThread(OHOS::UserIam::UserAuth::SendBootEvent);
    checkThread.join();
}

void CoAuthService::OnStop()
{
    if (state_ == CoAuthRunningState::STATE_STOPPED) {
        IAM_LOGW("CoAuthService already stopped");
        return;
    }
    state_ = CoAuthRunningState::STATE_STOPPED;
    IAM_LOGI("Stop service");
}

uint64_t CoAuthService::ExecutorRegister(const ExecutorRegisterInfo &info, sptr<ExecutorCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("executor callback is nullptr");
        return INVALID_EXECUTOR_INDEX;
    }
    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> fwkPublicKey;
    auto executorCallback = UserIAM::Common::SptrToStdSharedPtr<ExecutorCallback>(callback);
    auto resourceNode = ResourceNode::MakeNewResource(info, executorCallback, templateIdList, fwkPublicKey);
    if (resourceNode == nullptr) {
        IAM_LOGE("create resource node failed");
        return INVALID_EXECUTOR_INDEX;
    }
    if (!ResourceNodePool::Instance().Insert(resourceNode)) {
        IAM_LOGE("insert resource node failed");
        return INVALID_EXECUTOR_INDEX;
    }

    sptr<ExecutorMessenger> messenger = ExecutorMessengerService::GetInstance();
    executorCallback->OnMessengerReady(messenger, fwkPublicKey, templateIdList);
    uint64_t executorIndex = resourceNode->GetExecutorIndex();
    IAM_LOGI("register successful, executorType is %{public}u, executorIndex is ****%{public}u",
        static_cast<uint32_t>(resourceNode->GetAuthType()), static_cast<uint32_t>(executorIndex));
    return executorIndex;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS