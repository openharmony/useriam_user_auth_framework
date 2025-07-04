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

#ifndef IAM_RESOURCE_NODE_POOL_H
#define IAM_RESOURCE_NODE_POOL_H

#include <cstdint>
#include <functional>
#include <memory>

#include "resource_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ResourceNodePool {
public:
    class ResourceNodePoolListener {
    public:
        virtual ~ResourceNodePoolListener() = default;
        virtual void OnResourceNodePoolInsert(const std::shared_ptr<ResourceNode> &resource) = 0;
        virtual void OnResourceNodePoolDelete(const std::shared_ptr<ResourceNode> &resource) = 0;
        virtual void OnResourceNodePoolUpdate(const std::shared_ptr<ResourceNode> &resource) = 0;
    };
    static ResourceNodePool &Instance();
    virtual ~ResourceNodePool() = default;
    virtual bool Insert(const std::shared_ptr<ResourceNode> &resource) = 0;
    virtual bool Delete(uint64_t executorIndex) = 0;
    virtual void DeleteAll() = 0;
    virtual std::weak_ptr<ResourceNode> Select(uint64_t executorIndex) const = 0;
    virtual uint32_t GetPoolSize() const = 0;
    virtual void Enumerate(std::function<void(const std::weak_ptr<ResourceNode> &)> action) const = 0;
    virtual bool RegisterResourceNodePoolListener(const std::shared_ptr<ResourceNodePoolListener> &listener) = 0;
    virtual bool DeregisterResourceNodePoolListener(const std::shared_ptr<ResourceNodePoolListener> &listener) = 0;
    virtual void GetResourceNodeByTypeAndRole(AuthType authType,
        ExecutorRole role, std::vector<std::weak_ptr<ResourceNode>> &authTypeNodes) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_RESOURCE_NODE_POOL_H