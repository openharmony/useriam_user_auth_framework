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

#include "auth_executor_registry.h"

#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>

#include "iam_check.h"
#include "iam_logger.h"
#include "query_callback_stub.h"
#include "executor_callback_stub.h"

#define LOG_LABEL Common::LABEL_AUTH_EXECUTOR_MGR_SDK

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
sptr<CoAuth::ICoAuth> AuthExecutorRegistry::GetProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("get system ability manager failed");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR);
    if (obj == nullptr) {
        IAM_LOGE("get coauth service failed");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new (std::nothrow) AuthExecutorRegistryDeathRecipient();
    IF_FALSE_LOGE_AND_RETURN_VAL(dr != nullptr, nullptr);
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        IAM_LOGE("add death recipient failed");
        return nullptr;
    }

    proxy_ = iface_cast<CoAuth::ICoAuth>(obj);
    deathRecipient_ = dr;
    IAM_LOGI("connect coauth service success");
    return proxy_;
}

void AuthExecutorRegistry::ResetProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

uint64_t AuthExecutorRegistry::Register(std::shared_ptr<AuthExecutor> executorInfo,
    std::shared_ptr<ExecutorCallback> callback)
{
    IAM_LOGD("Register start");
    if (executorInfo == nullptr || callback == nullptr) {
        IAM_LOGE("executorInfo or callback is nullptr");
        return FAIL;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("proxy is nullptr");
        return FAIL;
    }
    sptr<IExecutorCallback> iExecutorCallback = new (std::nothrow) ExecutorCallbackStub(callback);
    IF_FALSE_LOGE_AND_RETURN_VAL(iExecutorCallback != nullptr, FAIL);
    return proxy->Register(executorInfo, iExecutorCallback);
}

void AuthExecutorRegistry::QueryStatus(AuthExecutor &executorInfo, std::shared_ptr<QueryCallback> callback)
{
    IAM_LOGD("QueryStatus start");
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        IAM_LOGE("proxy is nullptr");
        return;
    }
    sptr<IQueryCallback> iQueryCallback = new (std::nothrow) QueryCallbackStub(callback);
    IF_FALSE_LOGE_AND_RETURN(iQueryCallback != nullptr);
    return proxy->QueryStatus(executorInfo, iQueryCallback);
}

void AuthExecutorRegistry::AuthExecutorRegistryDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        IAM_LOGE("remote is nullptr");
        return;
    }

    AuthExecutorRegistry::GetInstance().ResetProxy(remote);
    IAM_LOGE("AuthExecutorRegistryDeathRecipient::Recv death notice");
}
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS