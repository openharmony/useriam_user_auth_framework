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

#include "auth_res_manager.h"
#include <cinttypes>
#include "executor_messenger.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
namespace UserAuthHdi = OHOS::HDI::UserAuth::V1_0;

bool AuthResManager::GetExecutorRegisterInfo(const std::shared_ptr<ResAuthExecutor> &executorInfo,
    UserAuthHdi::ExecutorRegisterInfo &info)
{
    std::vector<uint8_t> publicKey;
    executorInfo->GetPublicKey(publicKey);
    if (publicKey.size() != PUBLIC_KEY_LEN) {
        COAUTH_HILOGE(MODULE_SERVICE, "publicKey length is invalid");
        return false;
    }
    AuthType authType;
    executorInfo->GetAuthType(authType);
    ExecutorSecureLevel esl;
    executorInfo->GetExecutorSecLevel(esl);
    ExecutorType exeType;
    executorInfo->GetExecutorType(exeType);
    uint64_t authAbility;
    executorInfo->GetAuthAbility(authAbility);
    info.authType = static_cast<UserAuthHdi::AuthType>(authType);
    info.esl = static_cast<UserAuthHdi::ExecutorSecureLevel>(esl);
    info.executorRole = static_cast<UserAuthHdi::ExecutorRole>(exeType);
    info.executorMatcher = static_cast<uint32_t>(authAbility);
    info.publicKey.assign(publicKey.begin(), publicKey.end());
    return true;
}

/* Register the executor, pass in the executor information and the callback returns the executor ID. */
uint64_t AuthResManager::Register(std::shared_ptr<ResAuthExecutor> executorInfo, sptr<ResIExecutorCallback> callback)
{
    if (executorInfo == nullptr || callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorInfo or callback is nullptr");
        return INVALID_EXECUTOR_ID;
    }
    UserAuthHdi::ExecutorRegisterInfo info;
    if (!GetExecutorRegisterInfo(executorInfo, info)) {
        COAUTH_HILOGE(MODULE_SERVICE, "get register info failed");
        return INVALID_EXECUTOR_ID;
    }
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return INVALID_EXECUTOR_ID;
    }
    uint64_t executorId = INVALID_EXECUTOR_ID;
    std::vector<uint8_t> frameworksPublicKey;
    std::vector<uint64_t> templateIds;
    int32_t result = hdiInterface->AddExecutor(info, executorId, frameworksPublicKey, templateIds);
    if (result != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "register is failure!");
        return INVALID_EXECUTOR_ID;
    }
    sptr<IRemoteObject::DeathRecipient> dr =
        new (std::nothrow) ResIExecutorCallbackDeathRecipient(executorId, this);
    if (dr == nullptr || callback->AsObject() == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "dr or callback->AsObject() is nullptr");
        return INVALID_EXECUTOR_ID;
    }
    if (!callback->AsObject()->AddDeathRecipient(dr)) {
        COAUTH_HILOGE(MODULE_SERVICE, "add death recipient ResIExecutorCallbackDeathRecipient failed");
        return INVALID_EXECUTOR_ID;
    }
    coAuthResPool_.Insert(executorId, executorInfo, callback);

    // Assign messenger
    sptr<UserIAM::AuthResPool::IExecutorMessenger> messenger =
        new (std::nothrow) UserIAM::AuthResPool::ExecutorMessenger(&coAuthResPool_);
    if (messenger == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "messenger is nullptr");
        return INVALID_EXECUTOR_ID;
    }
    callback->OnMessengerReady(messenger, frameworksPublicKey, templateIds);
    COAUTH_HILOGD(MODULE_SERVICE, "register is successfull, exeID is 0xXXXX%{public}04" PRIx64, MASK & executorId);
    return executorId;
}

/* Query whether the executor is registered */
void AuthResManager::QueryStatus(ResAuthExecutor &executorInfo, sptr<ResIQueryCallback> callback)
{
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    callback->OnResult(FAIL); // Legacy interface, deleted later.
}

int32_t AuthResManager::FindExecutorCallback(uint64_t executorID,
                                             sptr<UserIAM::AuthResPool::IExecutorCallback> &callback)
{
    return coAuthResPool_.FindExecutorCallback(executorID, callback);
}

int32_t AuthResManager::FindExecutorCallback(uint32_t authType,
                                             sptr<UserIAM::AuthResPool::IExecutorCallback> &callback)
{
    return coAuthResPool_.FindExecutorCallback(authType, callback);
}

int32_t AuthResManager::DeleteExecutorCallback(uint64_t executorID)
{
    return coAuthResPool_.DeleteExecutorCallback(executorID);
}

int32_t AuthResManager::SaveScheduleCallback(uint64_t scheduleId, const CoAuth::ScheduleInfo &scheduleInfo,
    std::shared_ptr<CoAuthCallback> callback)
{
    return coAuthResPool_.Insert(scheduleId, scheduleInfo, callback);
}

int32_t AuthResManager::FindScheduleCallback(uint64_t scheduleId, std::shared_ptr<CoAuthCallback> &callback)
{
    return coAuthResPool_.FindScheduleCallback(scheduleId, callback);
}

int32_t AuthResManager::DeleteScheduleCallback(uint64_t scheduleId)
{
    return coAuthResPool_.DeleteScheduleCallback(scheduleId);
}

int32_t AuthResManager::FindScheduleInfo(uint64_t scheduleId, CoAuth::ScheduleInfo &info)
{
    return coAuthResPool_.GetScheduleInfo(scheduleId, info);
}

AuthResManager::ResIExecutorCallbackDeathRecipient::ResIExecutorCallbackDeathRecipient(
    uint64_t executorID, AuthResManager* parent) : executorID_(executorID), parent_(parent)
{
}

void AuthResManager::ResIExecutorCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ExecutorCallback OnRemoteDied failed, remote is nullptr");
        return;
    }

    if (parent_ != nullptr) {
        parent_->DeleteExecutorCallback(executorID_);
    }
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return;
    }
    int32_t ret = hdiInterface->DeleteExecutor(executorID_);
    if (ret != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "executor unregister failed");
    }
    COAUTH_HILOGW(MODULE_SERVICE, "ResIExecutorCallbackDeathRecipient::Recv death notice");
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS