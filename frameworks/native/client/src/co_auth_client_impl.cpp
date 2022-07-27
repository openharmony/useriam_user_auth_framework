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

#include "co_auth_client_impl.h"

#include "system_ability_definition.h"

#include "executor_callback_service.h"
#include "iam_logger.h"
#include "ipc_client_utils.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SDK

namespace OHOS {
namespace UserIam {
namespace UserAuth {
void CoAuthClientImpl::Register(const ExecutorInfo &info, const std::shared_ptr<ExecutorRegisterCallback> &callback)
{
    if (!callback) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    auto proxy = GetProxy();
    if (!proxy) {
        return;
    }

    CoAuthInterface::ExecutorRegisterInfo regInfo;
    regInfo.authType = info.authType;
    regInfo.executorRole = info.executorRole;
    regInfo.executorSensorHint = info.executorSensorHint;
    regInfo.executorMatcher = info.executorMatcher;
    regInfo.esl = info.esl;
    regInfo.publicKey = info.publicKey;

    sptr<ExecutorCallbackInterface> wrapper = new (std::nothrow) ExecutorCallbackService(callback);
    if (wrapper == nullptr) {
        IAM_LOGE("failed to create wrapper");
        return;
    }
    proxy->ExecutorRegister(regInfo, wrapper);
}

void CoAuthClientImpl::Unregister(const ExecutorInfo &info)
{
}

sptr<CoAuthInterface> CoAuthClientImpl::GetProxy()
{
    auto obj = IpcClientUtils::GetRemoteObject(SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR);
    if (!obj) {
        IAM_LOGE("failed to get service");
        return nullptr;
    }

    return iface_cast<CoAuthInterface>(obj);
}

CoAuthClient &CoAuthClient::GetInstance()
{
    static CoAuthClientImpl impl;
    return impl;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS