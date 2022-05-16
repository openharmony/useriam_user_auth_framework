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

#include "executor_messenger.h"
#include "securec.h"
#include "coauth_manager.h"
#include "call_monitor.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
ExecutorMessenger::ExecutorMessenger(UserIAM::CoAuth::AuthResPool* scheduleRes)
{
    ScheResPool_ = scheduleRes;
}

int32_t ExecutorMessenger::SendData(uint64_t scheduleId, uint64_t transNum, int32_t srcType,
                                    int32_t dstType, std::shared_ptr<AuthMessage> msg)
{
    if (ScheResPool_ == nullptr || msg == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ScheResPool_ or msg is nullptr");
        return FAIL;
    }

    std::shared_ptr<UserIAM::CoAuth::CoAuthCallback> callback;
    int32_t findRet = ScheResPool_->FindScheduleCallback(scheduleId, callback);
    if (findRet != SUCCESS || callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ScheduleCallback not find");
        return FAIL;
    }

    std::vector<uint8_t> message;
    msg->FromUint8Array(message);
    if (message.size() != sizeof(uint32_t)) {
        COAUTH_HILOGE(MODULE_SERVICE, "message size not right");
        return FAIL;
    }

    // trans to acquireCode
    uint32_t acquire = 0;
    if (memcpy_s(&acquire, sizeof(uint32_t), message.data(), message.size()) != EOK) {
        COAUTH_HILOGE(MODULE_SERVICE, "message copy not right");
        return FAIL;
    }
    callback->OnAcquireInfo(acquire);
    COAUTH_HILOGD(MODULE_SERVICE, "feedback acquire info");
    return SUCCESS;
}

int32_t ExecutorMessenger::Finish(uint64_t scheduleId, int32_t srcType, int32_t resultCode,
                                  std::shared_ptr<AuthAttributes> finalResult)
{
    COAUTH_HILOGD(MODULE_SERVICE, "ExecutorMessenger::Finish");
    if (ScheResPool_ == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ScheResPool_ is nullptr");
        return FAIL;
    }
    uint64_t scheCount;
    ScheResPool_->GetScheduleCount(scheduleId, scheCount);
    if (scheCount > 1) { // The last one will sign the token
        ScheResPool_->ScheduleCountMinus(scheduleId);
        return SUCCESS;
    }
    UserIAM::CoAuth::CallMonitor::GetInstance().MonitorRemoveCall(scheduleId);
    std::shared_ptr<UserIAM::CoAuth::CoAuthCallback> callback;
    int32_t findRet = ScheResPool_->FindScheduleCallback(scheduleId, callback);
    if (findRet != SUCCESS || callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "get schedule callback failed");
        return FAIL;
    }
    std::vector<uint8_t> scheduleResult;
    if (finalResult == nullptr) {
        callback->OnFinish(FAIL, scheduleResult);
        ScheResPool_->DeleteScheduleCallback(scheduleId);
        COAUTH_HILOGE(MODULE_SERVICE, "finalResult is nullptr");
        return FAIL;
    }

    if (resultCode == SUCCESS) {
        finalResult->GetUint8ArrayValue(AUTH_RESULT, scheduleResult);
    }
    callback->OnFinish(resultCode, scheduleResult);
    COAUTH_HILOGD(MODULE_SERVICE, "feedback finish info");
    ScheResPool_->DeleteScheduleCallback(scheduleId);
    return SUCCESS;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS