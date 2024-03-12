/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "template_cache_manager.h"

#include <mutex>

#include "os_account_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "context_pool.h"
#include "resource_node_pool.h"
#include "resource_node_utils.h"
#include "user_idm_database.h"
#include "thread_handler.h"

#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
int32_t GetCurrentUserId()
{
    std::vector<int32_t> ids;
    ErrCode queryRet = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (queryRet != ERR_OK || ids.empty()) {
        IAM_LOGE("failed to query active account id ret %{public}d count %{public}zu",
            queryRet, ids.size());
        return INVALID_USER_ID;
    }
    return ids.front();
}
}
using OsAccountSubscriber = AccountSA::OsAccountSubscriber;
using OsAccountSubscribeInfo = AccountSA::OsAccountSubscribeInfo;
using OS_ACCOUNT_SUBSCRIBE_TYPE = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE;

class ServiceStatusListener : public OHOS::SystemAbilityStatusChangeStub, public NoCopyable {
public:
    static sptr<ServiceStatusListener> GetInstance();
    static void Subscribe();

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    ServiceStatusListener() {};
    ~ServiceStatusListener() override {};
};

class OsAccountIdSubscriber : public OsAccountSubscriber, public NoCopyable {
public:
    explicit OsAccountIdSubscriber(const OsAccountSubscribeInfo &subscribeInfo);
    ~OsAccountIdSubscriber() = default;

    static std::shared_ptr<OsAccountIdSubscriber> GetInstance();
    static void Subscribe();
    static void Unsubscribe();
    void OnAccountsChanged(const int& id) override;

private:
    std::shared_ptr<ThreadHandler> threadHandler_;
};

void ServiceStatusListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
        return;
    }

    IAM_LOGI("os account service added");
    OsAccountIdSubscriber::Subscribe();
    IAM_LOGI("os account service add process finish");
}

void ServiceStatusListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    if (systemAbilityId != SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
        return;
    }

    IAM_LOGE("os account service removed");
    OsAccountIdSubscriber::Unsubscribe();
    ContextPool::Instance().CancelAll();
    IAM_LOGI("os account service remove process finish");
}

sptr<ServiceStatusListener> ServiceStatusListener::GetInstance()
{
    static sptr<ServiceStatusListener> listener(new (std::nothrow) ServiceStatusListener());
    if (listener == nullptr) {
        IAM_LOGE("ServiceStatusListener is null");
    }
    return listener;
}

void ServiceStatusListener::Subscribe()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        IAM_LOGE("failed to get SA manager");
        return;
    }

    auto instance = GetInstance();
    IF_FALSE_LOGE_AND_RETURN(instance != NULL);

    int32_t ret = sam->SubscribeSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, instance);
    if (ret != ERR_OK) {
        IAM_LOGE("failed to subscribe os account service status");
        return;
    }

    IAM_LOGI("subscribe os account SA service status success");
}

OsAccountIdSubscriber::OsAccountIdSubscriber(const OsAccountSubscribeInfo &subscribeInfo)
    : OsAccountSubscriber(subscribeInfo),
      threadHandler_(ThreadHandler::GetSingleThreadInstance())
{}

void OsAccountIdSubscriber::Subscribe()
{
    IAM_LOGI("start");
    auto instance = GetInstance();
    IF_FALSE_LOGE_AND_RETURN(instance != NULL);

    ErrCode errCode = AccountSA::OsAccountManager::SubscribeOsAccount(instance);
    if (errCode != ERR_OK) {
        IAM_LOGE("subscribe fail, errCode = %{public}d", errCode);
        return;
    }

    int32_t userId = GetCurrentUserId();
    if (userId == INVALID_USER_ID) {
        IAM_LOGE("GetCurrentUserId fail");
        return;
    }
    TemplateCacheManager::GetInstance().ProcessUserIdChange(userId);
    IAM_LOGI("subscribe success");
}

void OsAccountIdSubscriber::Unsubscribe()
{
    auto instance = GetInstance();
    IF_FALSE_LOGE_AND_RETURN(instance != NULL);

    ErrCode errCode = AccountSA::OsAccountManager::UnsubscribeOsAccount(instance);
    if (errCode != ERR_OK) {
        IAM_LOGE("unsubscribe fail, errCode = %{public}d", errCode);
        return;
    }
    IAM_LOGI("unsubscribe success");
}

void OsAccountIdSubscriber::OnAccountsChanged(const int& id)
{
    IAM_LOGI("OnAccountsChanged %{public}d", id);
    if (threadHandler_ == nullptr) {
        IAM_LOGE("threadHandler_ not set");
        return;
    }

    threadHandler_->PostTask([id]() {
        IAM_LOGI("task process begin");
        TemplateCacheManager::GetInstance().ProcessUserIdChange(id);
        IAM_LOGI("task process end");
    });
}

std::shared_ptr<OsAccountIdSubscriber> OsAccountIdSubscriber::GetInstance()
{
    OsAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED);

    static auto subscriber = Common::MakeShared<OsAccountIdSubscriber>(subscribeInfo);
    if (subscriber == nullptr) {
        IAM_LOGE("OsAccountIdSubscriber is null");
    }
    return subscriber;
}

TemplateCacheManager::TemplateCacheManager()
{
    ServiceStatusListener::Subscribe();
}

TemplateCacheManager &TemplateCacheManager::GetInstance()
{
    static TemplateCacheManager templateCacheManager;
    return templateCacheManager;
}

void TemplateCacheManager::ProcessUserIdChange(const int newUserId)
{
    std::lock_guard<std::recursive_mutex> lock(recursiveMutex_);
    if (newUserId == currUserId_) {
        IAM_LOGE("same userId %{public}d", newUserId);
        return;
    }

    IAM_LOGI("begin");
    currUserId_ = newUserId;
    UpdateTemplateCache(FACE);
    UpdateTemplateCache(FINGERPRINT);
    IAM_LOGI("done");
    return;
}

void TemplateCacheManager::UpdateTemplateCache(AuthType authType)
{
    std::lock_guard<std::recursive_mutex> lock(recursiveMutex_);
    IAM_LOGI("start");

    IF_FALSE_LOGE_AND_RETURN(currUserId_ != INVALID_USER_ID);
    if (authType != FACE && authType != FINGERPRINT) {
        IAM_LOGI("this auth type is not cached");
        return;
    }

    auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(currUserId_, authType);
    if (credentialInfos.empty()) {
        IAM_LOGI("user %{public}d has no credential type %{public}d", currUserId_, authType);
        ResourceNodePool::Instance().Enumerate([authType](const std::weak_ptr<ResourceNode> &node) {
            auto nodeTmp = node.lock();
            IF_FALSE_LOGE_AND_RETURN(nodeTmp != nullptr);

            if (nodeTmp->GetAuthType() != authType) {
                return;
            }
            IAM_LOGI("clear cached template for type %{public}d", authType);
            ResourceNodeUtils::SetCachedTemplates(nodeTmp->GetExecutorIndex(),
                std::vector<std::shared_ptr<CredentialInfoInterface>>());
        });
        return;
    }

    IAM_LOGI("user %{public}d type %{public}d credential info size %{public}zu",
        currUserId_, authType, credentialInfos.size());
    std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> id2Cred;
    ResultCode result = ResourceNodeUtils::ClassifyCredInfoByExecutor(credentialInfos, id2Cred);
    IF_FALSE_LOGE_AND_RETURN(result == SUCCESS);

    for (auto const &pair : id2Cred) {
        ResourceNodeUtils::SetCachedTemplates(pair.first, pair.second);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS