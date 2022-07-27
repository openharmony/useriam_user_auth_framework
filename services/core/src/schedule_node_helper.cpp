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
#include "schedule_node_helper.h"

#include <cinttypes>

#include "iam_logger.h"
#include "resource_node_pool.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA
namespace OHOS {
namespace UserIam {
namespace UserAuth {
bool ScheduleNodeHelper::BuildFromHdi(const std::vector<HdiScheduleInfo> &infos,
    std::shared_ptr<ScheduleNodeCallback> callback, std::vector<std::shared_ptr<ScheduleNode>> &nodes)
{
    NodeOptionalPara para;
    return BuildFromHdi(infos, callback, nodes, para);
}

bool ScheduleNodeHelper::BuildFromHdi(const std::vector<HdiScheduleInfo> &infos,
    std::shared_ptr<ScheduleNodeCallback> callback, std::vector<std::shared_ptr<ScheduleNode>> &nodes,
    const NodeOptionalPara &para)
{
    std::vector<std::shared_ptr<ScheduleNode>> outputs;

    for (const auto &info : infos) {
        std::shared_ptr<ScheduleNode> node;
        if (!ScheduleInfoToScheduleNode(info, node, para, callback)) {
            IAM_LOGE("ScheduleInfoToScheduleNode error");
            return false;
        }
        outputs.push_back(node);
    }

    nodes.swap(outputs);
    return true;
}

bool ScheduleNodeHelper::ScheduleInfoToScheduleNode(const HdiScheduleInfo &info, std::shared_ptr<ScheduleNode> &node,
    const NodeOptionalPara &para, const std::shared_ptr<ScheduleNodeCallback> &callback)
{
    if (info.executors.empty()) {
        IAM_LOGE("executors empty");
        return false;
    }
    std::shared_ptr<ResourceNode> collector;
    std::shared_ptr<ResourceNode> verifier;

    if (!ScheduleInfoToExecutors(info, collector, verifier)) {
        IAM_LOGE("ScheduleInfoToExecutors error");
        return false;
    }

    auto builder = ScheduleNode::Builder::New(collector, verifier);
    if (builder == nullptr) {
        IAM_LOGE("invalid builder");
        return false;
    }
    if (para.tokenId.has_value()) {
        builder->SetAccessTokenId(para.tokenId.value());
    }
    node = builder->SetAuthType(static_cast<AuthType>(info.authType))
               ->SetExecutorMatcher(info.executorMatcher)
               ->SetScheduleId(info.scheduleId)
               ->SetTemplateIdList(info.templateIds)
               ->SetScheduleMode(static_cast<ScheduleMode>(info.scheduleMode))
               ->SetExpiredTime(para.expire.value_or(0))
               ->SetPinSubType(para.pinSubType.value_or(PinSubType::PIN_MAX))
               ->SetScheduleCallback(callback)
               ->Build();
    if (node == nullptr) {
        IAM_LOGE("builder failed");
        return false;
    }
    return true;
}

bool ScheduleNodeHelper::ScheduleInfoToExecutors(const HdiScheduleInfo &info, std::shared_ptr<ResourceNode> &collector,
    std::shared_ptr<ResourceNode> &verifier)
{
    for (const auto &executor : info.executors) {
        auto resource = ResourceNodePool::Instance().Select(executor.executorIndex).lock();
        if (resource == nullptr) {
            IAM_LOGI("invalid executorId ****%{public}hx", static_cast<uint16_t>(executor.executorIndex));
            return false;
        }
        switch (resource->GetExecutorRole()) {
            case COLLECTOR: {
                collector = resource;
                break;
            }
            case VERIFIER: {
                verifier = resource;
                break;
            }
            case ALL_IN_ONE: {
                collector = resource;
                verifier = resource;
                break;
            }
            default: {
                IAM_LOGE("invalid executor role");
                break;
            }
        }
    }
    if (collector == nullptr) {
        IAM_LOGE("invalid executor collector");
        return false;
    }
    if (verifier == nullptr) {
        IAM_LOGE("invalid executor verifier");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS