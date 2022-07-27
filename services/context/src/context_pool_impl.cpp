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

#include "context_pool.h"

#include <mutex>
#include <set>
#include <singleton.h>
#include <unordered_map>

#include <openssl/rand.h>

#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextPoolImpl final : public ContextPool, public Singleton<ContextPoolImpl> {
public:
    bool Insert(const std::shared_ptr<Context> &context) override;
    bool Delete(uint64_t contextId) override;
    std::weak_ptr<Context> Select(uint64_t contextId) const override;
    std::vector<std::weak_ptr<Context>> Select(ContextType contextType) const override;
    std::shared_ptr<ScheduleNode> SelectScheduleNodeByScheduleId(uint64_t scheduleId) override;
    bool RegisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener) override;
    bool DeregisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener) override;

private:
    mutable std::mutex poolMutex_;
    std::unordered_map<uint64_t, std::shared_ptr<Context>> contextMap_;
    std::set<std::shared_ptr<ContextPoolListener>> listenerSet_;
};

bool ContextPoolImpl::Insert(const std::shared_ptr<Context> &context)
{
    if (context == nullptr) {
        IAM_LOGE("context is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(poolMutex_);
    uint64_t contextId = context->GetContextId();
    auto result = contextMap_.try_emplace(contextId, context);
    if (!result.second) {
        return false;
    }
    for (const auto &listener : listenerSet_) {
        if (listener != nullptr) {
            listener->OnContextPoolInsert(context);
        }
    }
    return true;
}

bool ContextPoolImpl::Delete(uint64_t contextId)
{
    std::lock_guard<std::mutex> lock(poolMutex_);
    auto iter = contextMap_.find(contextId);
    if (iter == contextMap_.end()) {
        IAM_LOGE("context not found");
        return false;
    }
    auto tempContext = iter->second;
    contextMap_.erase(iter);
    for (const auto &listener : listenerSet_) {
        if (listener != nullptr) {
            listener->OnContextPoolDelete(tempContext);
        }
    }
    return true;
}

std::weak_ptr<Context> ContextPoolImpl::Select(uint64_t contextId) const
{
    std::lock_guard<std::mutex> lock(poolMutex_);
    std::weak_ptr<Context> result;
    auto iter = contextMap_.find(contextId);
    if (iter != contextMap_.end()) {
        result = iter->second;
    }
    return result;
}

std::vector<std::weak_ptr<Context>> ContextPoolImpl::Select(ContextType contextType) const
{
    std::lock_guard<std::mutex> lock(poolMutex_);
    std::vector<std::weak_ptr<Context>> result;
    for (const auto &context : contextMap_) {
        if (context.second == nullptr) {
            continue;
        }
        if (context.second->GetContextType() == contextType) {
            result.emplace_back(context.second);
        }
    }
    return result;
}

std::shared_ptr<ScheduleNode> ContextPoolImpl::SelectScheduleNodeByScheduleId(uint64_t scheduleId)
{
    std::lock_guard<std::mutex> lock(poolMutex_);
    for (const auto &context : contextMap_) {
        if (context.second == nullptr) {
            continue;
        }
        auto node = context.second->GetScheduleNode(scheduleId);
        if (node != nullptr) {
            return node;
        }
    }
    return nullptr;
}

bool ContextPoolImpl::RegisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener)
{
    if (listener == nullptr) {
        IAM_LOGE("listener is nullptr");
        return false;
    }
    std::lock_guard<std::mutex> lock(poolMutex_);
    listenerSet_.insert(listener);
    return true;
}

bool ContextPoolImpl::DeregisterContextPoolListener(const std::shared_ptr<ContextPoolListener> &listener)
{
    std::lock_guard<std::mutex> lock(poolMutex_);
    return listenerSet_.erase(listener) == 1;
}

ContextPool &ContextPool::Instance()
{
    return ContextPoolImpl::GetInstance();
}

uint64_t ContextPool::GetNewContextId()
{
    static constexpr uint32_t MAX_TRY_TIMES = 10;
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    uint64_t contextId = 0;
    unsigned char *contextIdPtr = static_cast<unsigned char *>(static_cast<void *>(&contextId));
    for (uint32_t i = 0; i < MAX_TRY_TIMES; i++) {
        RAND_bytes(contextIdPtr, sizeof(uint64_t));
        if (contextId == 0 || ContextPool::Instance().Select(contextId).lock() != nullptr) {
            IAM_LOGE("invalid or duplicate context id");
            continue;
        }
    }
    return contextId;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
