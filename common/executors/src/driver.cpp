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

#include "driver.h"

#include "executor_mgr_wrapper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iauth_driver_hdi.h"
#include "iauth_executor_hdi.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIam {
namespace UserAuth {
Driver::Driver(const std::string &serviceName, HdiConfig hdiConfig) : serviceName_(serviceName), hdiConfig_(hdiConfig)
{
}

void Driver::OnHdiConnect()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (hdiConnected_) {
        IAM_LOGI("already connected skip");
        return;
    }
    std::vector<std::shared_ptr<IAuthExecutorHdi>> executorHdiList;
    IF_FALSE_LOGE_AND_RETURN(hdiConfig_.driver != nullptr);
    hdiConfig_.driver->GetExecutorList(executorHdiList);
    IAM_LOGI("executorHdiList length is %{public}zu", executorHdiList.size());
    auto executorMgrWrapper = Common::MakeShared<ExecutorMgrWrapper>();
    IF_FALSE_LOGE_AND_RETURN(executorMgrWrapper != nullptr);
    hdiConnected_ = true;
    for (const auto &executorHdi : executorHdiList) {
        if (executorHdi == nullptr) {
            IAM_LOGI("executorHdi is nullptr, skip");
            continue;
        }
        auto executor = Common::MakeShared<Executor>(executorMgrWrapper, executorHdi, hdiConfig_.id);
        if (executor == nullptr) {
            IAM_LOGE("MakeShared failed");
            continue;
        }
        executorList_.push_back(executor);
        executor->OnHdiConnect();
        IAM_LOGI("add executor %{public}s success", executor->GetDescription());
    }
    IAM_LOGI("success");
}

void Driver::OnHdiDisconnect()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    hdiConnected_ = false;
    for (const auto &executor : executorList_) {
        if (executor == nullptr) {
            IAM_LOGE("executor is null");
            continue;
        }
        executor->OnHdiDisconnect();
    }
    executorList_.clear();
    IAM_LOGI("success");
}

void Driver::OnFrameworkReady()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &executor : executorList_) {
        if (executor == nullptr) {
            IAM_LOGE("executor is null");
            continue;
        }
        executor->OnFrameworkReady();
    }
    IAM_LOGI("success");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
