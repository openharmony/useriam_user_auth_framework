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
#include <mutex>
#include <thread>

#include "string_ex.h"

#include "executor_messenger_service.h"
#include "hdi_wrapper.h"
#include "hisysevent_adapter.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_para2str.h"
#include "ipc_common.h"
#include "iam_time.h"
#include "iam_common_defines.h"
#include "parameter.h"
#include "relative_timer.h"
#include "resource_node_pool.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

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
    static std::mutex mutex;
    static uint32_t timerId = 0;
    std::lock_guard<std::mutex> guard(mutex);
    IAM_LOGI("Start service");
    if (!Publish(this)) {
        IAM_LOGE("Failed to publish service");
        return;
    }

    if (timerId != 0) {
        RelativeTimer::GetInstance().Unregister(timerId);
    }
    timerId = RelativeTimer::GetInstance().Register(Init, 0);
}

void CoAuthService::OnStop()
{
    IAM_LOGI("Stop service");
}

uint64_t CoAuthService::ExecutorRegister(const ExecutorRegisterInfo &info, sptr<ExecutorCallbackInterface> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("executor callback is nullptr");
        return INVALID_EXECUTOR_INDEX;
    }
    if (!IpcCommon::CheckPermission(*this, ACCESS_AUTH_RESPOOL)) {
        IAM_LOGE("failed to check permission");
        return INVALID_EXECUTOR_INDEX;
    }
    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> fwkPublicKey;
    auto executorCallback = Common::SptrToStdSharedPtr<ExecutorCallbackInterface>(callback);
    auto resourceNode = ResourceNode::MakeNewResource(info, executorCallback, templateIdList, fwkPublicKey);
    if (resourceNode == nullptr) {
        IAM_LOGE("create resource node failed");
        return INVALID_EXECUTOR_INDEX;
    }
    if (!ResourceNodePool::Instance().Insert(resourceNode)) {
        IAM_LOGE("insert resource node failed");
        return INVALID_EXECUTOR_INDEX;
    }

    sptr<ExecutorMessengerInterface> messenger = ExecutorMessengerService::GetInstance();
    executorCallback->OnMessengerReady(messenger, fwkPublicKey, templateIdList);
    uint64_t executorIndex = resourceNode->GetExecutorIndex();
    int32_t executorType = resourceNode->GetAuthType();
    IAM_LOGI("register successful, executorType is %{public}d, executorIndex is ****%{public}hx",
        executorType, static_cast<uint16_t>(executorIndex));
    if (auto obj = executorCallback->AsObject(); obj) {
        obj->AddDeathRecipient(new (std::nothrow) IpcCommon::PeerDeathRecipient([executorIndex, executorType]() {
            auto result = ResourceNodePool::Instance().Delete(executorIndex);
            IAM_LOGI("delete executor %{public}s, executorIndex is ****%{public}hx", (result ? "succ" : "failed"),
                static_cast<uint16_t>(executorIndex));
            std::string executorDesc = "executor, type " + std::to_string(executorType);
            UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), executorDesc);
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
            UserIam::UserAuth::ReportSystemFault(Common::GetNowTimeString(), "user_auth_hdi host");
        }));
        IAM_LOGI("set fwk ready parameter");
        SetParameter("bootevent.useriam.fwkready", "false");
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
                dprintf(fd, "ExecutorType is: %s.\n", Common::AuthTypeToStr(nodeTmp->GetAuthType()));
            }
        });
        return SUCCESS;
    }
    IAM_LOGE("invalid option");
    dprintf(fd, "Invalid option\n");
    return GENERAL_ERROR;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS