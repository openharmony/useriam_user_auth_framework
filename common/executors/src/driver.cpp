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
#include <mutex>
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iauth_driver_hdi.h"
#include "iauth_executor_hdi.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_EXECUTOR

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
Driver::Driver(const std::string &serviceName, HdiConfig hdiConfig) : serviceName_(serviceName), hdiConfig_(hdiConfig)
{
}

void Driver::OnHdiConnect()
{
    IAM_LOGI("start");
    OnHdiDisconnect();
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<std::shared_ptr<IAuthExecutorHdi>> executorHdiList;
    hdiConfig_.driver->GetExecutorList(executorHdiList);
    IAM_LOGI("executorHdiList length is %{public}zu", executorHdiList.size());
    for (const auto &executorHdi : executorHdiList) {
        auto executor = Common::MakeShared<Executor>(executorHdi, hdiConfig_.id);
        if (executor == nullptr) {
            IAM_LOGE("make_shared failed");
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
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (const auto &executor : executorList_) {
        // executor is non-null
        executor->OnHdiDisconnect();
    }
    executorList_.clear();
    IAM_LOGI("success");
}

void Driver::OnFrameworkReady()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (const auto &executor : executorList_) {
        // executor is non-null
        executor->OnFrameworkReady();
    }
    IAM_LOGI("success");
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
