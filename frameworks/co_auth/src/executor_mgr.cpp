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

#include "executor_mgr.h"

#include "auth_executor_registry.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL UserIAM::Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void ExecutorMgr::Register(const ExecutorInfo &info, std::shared_ptr<ExecutorCallback> callback)
{
    auto executorInfo = UserIAM::Common::MakeShared<AuthExecutor>();
    IF_FALSE_LOGE_AND_RETURN(executorInfo != nullptr);
    executorInfo->SetPublicKey(info.publicKey);
    executorInfo->SetExecutorSecLevel(info.esl);
    executorInfo->SetAuthAbility(static_cast<uint64_t>(info.executorType));
    executorInfo->SetAuthType(info.authType);
    executorInfo->SetExecutorType(static_cast<ExecutorType>(info.role));
    AuthExecutorRegistry::GetInstance().Register(executorInfo, callback);
}
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS