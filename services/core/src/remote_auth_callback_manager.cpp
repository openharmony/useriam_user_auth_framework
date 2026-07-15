/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "remote_auth_callback_manager.h"

#include <mutex>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "ipc_common.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_REMOTE_AUTH_CALLBACK_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
RemoteAuthCallbackManager::RemoteAuthCallbackManager()
{
    IAM_LOGI("init");
}

RemoteAuthCallbackManager &RemoteAuthCallbackManager::GetInstance()
{
    static RemoteAuthCallbackManager remoteAuthCallbackManager;
    return remoteAuthCallbackManager;
}

int32_t RemoteAuthCallbackManager::AddRemoteAuthCallback(uint32_t tokenId,
    const sptr<IRemoteAuthCallback> &remoteAuthCallback)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (callbackMap_.find(tokenId) != callbackMap_.end()) {
        IAM_LOGE("remoteAuthCallback is already register, do not repeat");
        return GENERAL_ERROR;
    }

    if (remoteAuthCallback == nullptr) {
        IAM_LOGE("remoteAuthCallback is nullptr");
        return GENERAL_ERROR;
    }

    callbackMap_.emplace(tokenId, remoteAuthCallback);

    sptr<IRemoteObject::DeathRecipient> dr(new (std::nothrow) RemoteAuthCallbackDeathRecipient(tokenId));
    if (dr == nullptr || remoteAuthCallback->AsObject() == nullptr) {
        IAM_LOGE("dr or inputer's object is nullptr");
    } else {
        remoteDeathMap_.emplace(tokenId, dr);
        if (!remoteAuthCallback->AsObject()->AddDeathRecipient(dr)) {
            IAM_LOGE("add death recipient fail");
        }
    }
    IAM_LOGI("end");
    return SUCCESS;
}

void RemoteAuthCallbackManager::DelRemoteAuthCallback(uint32_t tokenId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (callbackMap_.find(tokenId) != callbackMap_.end()) {
        if (remoteDeathMap_.find(tokenId) != remoteDeathMap_.end()) {
            auto remoteAuthCallback = callbackMap_[tokenId];
            if (remoteAuthCallback == nullptr || remoteAuthCallback->AsObject() == nullptr) {
                IAM_LOGE("remoteAuthCallback is nullptr");
            } else if (!remoteAuthCallback->AsObject()->RemoveDeathRecipient(remoteDeathMap_[tokenId])) {
                IAM_LOGE("remove death recipient fail");
            }
            remoteDeathMap_.erase(tokenId);
        }
        callbackMap_.erase(tokenId);
        IAM_LOGE("callbackMap_ erase success");
    }
    IAM_LOGI("end");
}

sptr<IRemoteAuthCallback> RemoteAuthCallbackManager::GetRemoteAuthCallback(uint32_t tokenId)
{
    std::lock_guard<std::mutex> guard(mutex_);
    IAM_LOGI("start");
    auto remoteAuthCallback = callbackMap_.find(tokenId);
    if (remoteAuthCallback != callbackMap_.end()) {
        IAM_LOGI("find remoteAuthCallback");
        return remoteAuthCallback->second;
    } else {
        IAM_LOGE("remoteAuthCallback is not found");
    }
    return nullptr;
}

std::string RemoteAuthCallbackManager::GetRemoteAuthCallerName(uint32_t tokenId)
{
    IAM_LOGI("start");
    std::string callerName;
    int32_t callerType;
    if ((!IpcCommon::GetCallerNameByTokenId(tokenId, callerName, callerType))) {
        IAM_LOGE("get caller name fail");
        return "";
    }
    return callerName;
}

RemoteAuthCallbackManager::RemoteAuthCallbackDeathRecipient::RemoteAuthCallbackDeathRecipient(uint32_t tokenId)
    : tokenId_(tokenId)
{
}

void RemoteAuthCallbackManager::RemoteAuthCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    IAM_LOGI("start");
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }
    RemoteAuthCallbackManager::GetInstance().DelRemoteAuthCallback(tokenId_);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS