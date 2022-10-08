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

#include "executor_messenger_service.h"

#include <cinttypes>

#include "iam_logger.h"
#include "iam_common_defines.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ExecutorMessengerService::ExecutorMessengerService()
{
    IAM_LOGI("ExecutorMessengerService init");
}

sptr<ExecutorMessengerService> ExecutorMessengerService::GetInstance()
{
    static sptr<ExecutorMessengerService> instance = new (std::nothrow) ExecutorMessengerService();
    if (instance == nullptr) {
        IAM_LOGE("instance is nullptr");
    }
    return instance;
}

int32_t ExecutorMessengerService::SendData(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole,
    ExecutorRole dstRole, const std::vector<uint8_t> &msg)
{
    auto scheduleNode = ContextPool::Instance().SelectScheduleNodeByScheduleId(scheduleId);
    if (scheduleNode == nullptr) {
        IAM_LOGE("selected schedule node is nullptr");
        return GENERAL_ERROR;
    }
    bool result = scheduleNode->ContinueSchedule(srcRole, dstRole, transNum, msg);
    if (!result) {
        IAM_LOGE("continue schedule failed");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t ExecutorMessengerService::Finish(uint64_t scheduleId, ExecutorRole srcRole, ResultCode resultCode,
    const std::shared_ptr<Attributes> &finalResult)
{
    auto scheduleNode = ContextPool::Instance().SelectScheduleNodeByScheduleId(scheduleId);
    if (scheduleNode == nullptr) {
        IAM_LOGE("selected schedule node is nullptr");
        return GENERAL_ERROR;
    }
    bool result = scheduleNode->ContinueSchedule(resultCode, finalResult);
    if (!result) {
        IAM_LOGE("continue schedule failed");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS