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

#include "string_ex.h"

#include "executor_messenger_service.h"
#include "hdi_wrapper.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "ipc_common.h"
#include "parameter.h"
#include "relative_timer.h"
#include "resource_node_pool.h"
#include "result_code.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
REGISTER_SYSTEM_ABILITY_BY_ID(CoAuthService, SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR, true);
CoAuthService::CoAuthService(int32_t systemAbilityId, bool runOnCreate) : SystemAbility(systemAbilityId, runOnCreate)
{
    IAM_LOGI("CoAuthService init");
}

void CoAuthService::OnStart()
{
    IAM_LOGI("Start service");
    if (!Publish(this)) {
        IAM_LOGE("Failed to publish service");
        return;
    }

    RelativeTimer::GetInstance().Register(Init, 0);
}

void CoAuthService::OnStop()
{
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
    IAM_LOGI("register successful, executorType is %{public}u, executorIndex is ****%{public}hx",
        static_cast<uint32_t>(resourceNode->GetAuthType()), static_cast<uint16_t>(executorIndex));
    if (auto obj = executorCallback->AsObject(); obj) {
        obj->AddDeathRecipient(new (std::nothrow) IpcCommon::PeerDeathRecipient([executorIndex]() {
            auto result = ResourceNodePool::Instance().Delete(executorIndex);
            IAM_LOGI("delete executor %{public}s, executorIndex is ****%{public}hx", (result ? "succ" : "failed"),
                static_cast<uint16_t>(executorIndex));
        }));
    }
    return executorIndex;
}

void CoAuthService::Init()
{
    auto hdi = HdiWrapper::GetHdiRemoteObjInstance();
    if (hdi) {
        hdi->AddDeathRecipient(new (std::nothrow) IpcCommon::PeerDeathRecipient([]() {
            ResourceNodePool::Instance().DeleteAll();
            RelativeTimer::GetInstance().Register(Init, DEFER_TIME);
            IAM_LOGI("delete all executors for hdi dead");
        }));
        IAM_LOGI("set fwk ready parameter");
        SetParameter("bootevent.useriam.fwkready", "true");
    } else {
        RelativeTimer::GetInstance().Register(Init, DEFER_TIME);
    }
}

int CoAuthService::Dump(int fd, const std::vector<std::u16string> &args)
{
    IAM_LOGI("start");
    if (fd < 0) {
        IAM_LOGE("invalid parameters");
        dprintf(fd, "Invalid parameters.\n");
        return INVALID_PARAMETERS;
    }
    std::string arg0 = (args.empty() ? "" : Str16ToStr8(args[0]));
    if (arg0.empty() || arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "      -h: command help.\n");
        dprintf(fd, "      -l: resource pool dump.\n");
        return SUCCESS;
    }
    if (arg0.compare("-l") == 0) {
        ResourceNodePool::Instance().Enumerate([fd](const std::weak_ptr<ResourceNode> &node) {
            auto nodeTmp = node.lock();
            if (nodeTmp != nullptr) {
                dprintf(fd, "ExecutorIndex is: %" PRIx64 ".\n", nodeTmp->GetExecutorIndex());
                dprintf(fd, "ExecutorType is: %s.\n", AuthTypeToStr(nodeTmp->GetAuthType()));
            }
        });
        return SUCCESS;
    }
    IAM_LOGE("invalid option");
    dprintf(fd, "Invalid option\n");
    return FAIL;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS