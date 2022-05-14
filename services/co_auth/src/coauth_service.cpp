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

#include "coauth_service.h"
#include <cinttypes>
#include <file_ex.h>
#include <string_ex.h>
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <unistd.h>
#include <thread>
#include "parameter.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
void SendBootEvent()
{
    COAUTH_HILOGI(MODULE_SERVICE, "SendBootEvent start");
    SetParameter("bootevent.useriam.fwkready", "true");
}

REGISTER_SYSTEM_ABILITY_BY_ID(CoAuthService, SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR, true);
CoAuthService::CoAuthService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
    CoAuthManager::GetInstance().RegistResourceManager(&authResMgr_);
}

CoAuthService::~CoAuthService()
{
}

void CoAuthService::OnStart()
{
    if (state_ == CoAuthRunningState::STATE_RUNNING) {
        COAUTH_HILOGW(MODULE_SERVICE, "CoAuthService has already started");
        return;
    }
    COAUTH_HILOGI(MODULE_SERVICE, "Start service");
    if (!Publish(this)) {
        COAUTH_HILOGE(MODULE_SERVICE, "Failed to publish service");
        return;
    }
    state_ = CoAuthRunningState::STATE_RUNNING;
    // Start other service
    std::thread checkThread(OHOS::UserIAM::CoAuth::SendBootEvent);
    checkThread.join();
}

void CoAuthService::OnStop()
{
    if (state_ == CoAuthRunningState::STATE_STOPPED) {
        COAUTH_HILOGW(MODULE_SERVICE, "CoAuthService already stopped");
        return;
    }
    state_ = CoAuthRunningState::STATE_STOPPED;
    COAUTH_HILOGI(MODULE_SERVICE, "Stop service");
}

/* Register the executor, pass in the executor information and the callback returns the executor ID. */
uint64_t CoAuthService::Register(std::shared_ptr<ResAuthExecutor> executorInfo,
                                 const sptr<ResIExecutorCallback> &callback)
{
    if (executorInfo == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorInfo is nullptr");
        return FAIL;
    }

    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return FAIL;
    }

    uint64_t exeID = authResMgr_.Register(executorInfo, callback);
    COAUTH_HILOGD(MODULE_SERVICE, "exeID is 0xXXXX%{public}04" PRIx64, MASK & exeID);
    return exeID;
}

/* Query whether the executor is registered */
void CoAuthService::QueryStatus(ResAuthExecutor &executorInfo, const sptr<ResIQueryCallback> &callback)
{
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    return authResMgr_.QueryStatus(executorInfo, callback);
}
} // namespace CoAu
} // namespace UserIAM
} // namespace OHOS
