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

#include "resource_node_pool.h"

#include <mutex>
#include <set>
#include <unordered_map>

#include <singleton.h>

#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ResourceNodePoolImpl final : public ResourceNodePool, public Singleton<ResourceNodePoolImpl> {
public:
    bool Insert(const std::shared_ptr<ResourceNode> &resource) override;
    bool Delete(uint64_t executorIndex) override;
    void DeleteAll() override;
    std::weak_ptr<ResourceNode> Select(uint64_t executorIndex) const override;
    uint32_t GetPoolSize() const override;
    void Enumerate(std::function<void(const std::weak_ptr<ResourceNode> &)> action) const override;
    bool RegisterResourceNodePoolListener(const std::shared_ptr<ResourceNodePoolListener> &listener) override;
    bool DeregisterResourceNodePoolListener(const std::shared_ptr<ResourceNodePoolListener> &listener) override;

private:
    struct ResourceNodeParam {
        uint32_t count = 0;
        std::shared_ptr<ResourceNode> node = nullptr;
    };
    mutable std::recursive_mutex poolMutex_;
    std::unordered_map<uint64_t, ResourceNodeParam> resourceNodeMap_;
    std::set<std::shared_ptr<ResourceNodePoolListener>> listenerSet_;
};

bool ResourceNodePoolImpl::Insert(const std::shared_ptr<ResourceNode> &resource)
{
    if (resource == nullptr) {
        IAM_LOGE("resource is nullptr");
        return false;
    }
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    uint64_t executorIndex = resource->GetExecutorIndex();

    ResourceNodeParam nodeParam = {1, resource};
    auto iter = resourceNodeMap_.find(executorIndex);
    if (iter != resourceNodeMap_.end()) {
        if (nodeParam.count < UINT32_MAX) {
            nodeParam.count = iter->second.count + 1;
        }
        iter->second.node->Detach();
    }

    auto result = resourceNodeMap_.insert_or_assign(executorIndex, nodeParam);
    if (result.second) {
        IAM_LOGI("insert resource node success");
        for (const auto &listener : listenerSet_) {
            if (listener != nullptr) {
                listener->OnResourceNodePoolInsert(nodeParam.node);
            }
        }
    } else {
        IAM_LOGI("update resource node success, count: %{public}u", resourceNodeMap_[executorIndex].count);
        for (const auto &listener : listenerSet_) {
            if (listener != nullptr) {
                listener->OnResourceNodePoolUpdate(nodeParam.node);
            }
        }
    }
    return true;
}

bool ResourceNodePoolImpl::Delete(uint64_t executorIndex)
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    auto iter = resourceNodeMap_.find(executorIndex);
    if (iter == resourceNodeMap_.end()) {
        IAM_LOGE("executor not found");
        return false;
    }

    if (iter->second.count > 1) {
        iter->second.count--;
        IAM_LOGI("resource node count %{public}u, no delete", iter->second.count);
        return true;
    }
    IAM_LOGI("delete resource node");

    auto tempResource = iter->second.node;
    resourceNodeMap_.erase(iter);
    for (const auto &listener : listenerSet_) {
        if (listener != nullptr) {
            listener->OnResourceNodePoolDelete(tempResource);
        }
    }
    return true;
}

void ResourceNodePoolImpl::DeleteAll()
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    auto tempMap = resourceNodeMap_;
    resourceNodeMap_.clear();
    for (auto &node : tempMap) {
        for (const auto &listener : listenerSet_) {
            if (listener != nullptr) {
                listener->OnResourceNodePoolDelete(node.second.node);
            }
        }
    }
}

std::weak_ptr<ResourceNode> ResourceNodePoolImpl::Select(uint64_t executorIndex) const
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    std::weak_ptr<ResourceNode> result;
    auto iter = resourceNodeMap_.find(executorIndex);
    if (iter != resourceNodeMap_.end()) {
        result = iter->second.node;
    }
    return result;
}

void ResourceNodePoolImpl::Enumerate(std::function<void(const std::weak_ptr<ResourceNode> &)> action) const
{
    if (action == nullptr) {
        IAM_LOGE("action is nullptr");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    for (auto &node : resourceNodeMap_) {
        action(node.second.node);
    }
}

uint32_t ResourceNodePoolImpl::GetPoolSize() const
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    return resourceNodeMap_.size();
}

bool ResourceNodePoolImpl::RegisterResourceNodePoolListener(const std::shared_ptr<ResourceNodePoolListener> &listener)
{
    if (listener == nullptr) {
        IAM_LOGE("listener is nullptr");
        return false;
    }
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    listenerSet_.insert(listener);
    return true;
}

bool ResourceNodePoolImpl::DeregisterResourceNodePoolListener(const std::shared_ptr<ResourceNodePoolListener> &listener)
{
    std::lock_guard<std::recursive_mutex> lock(poolMutex_);
    return listenerSet_.erase(listener) == 1;
}

ResourceNodePool &ResourceNodePool::Instance()
{
    return ResourceNodePoolImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
