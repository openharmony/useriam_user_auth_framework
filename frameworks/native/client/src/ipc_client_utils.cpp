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
#include "ipc_client_utils.h"

#include "iservice_registry.h"

#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
sptr<IRemoteObject> IpcClientUtils::GetRemoteObject(int32_t saId)
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sam) {
        IAM_LOGE("failed to get system ability manager");
        return nullptr;
    }

    auto obj = sam->CheckSystemAbility(saId);
    if (!obj) {
        IAM_LOGE("failed to get service");
        return nullptr;
    }
    return obj;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS