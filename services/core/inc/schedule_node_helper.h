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

#ifndef IAM_SCHEDULE_NODE_HELPER_H
#define IAM_SCHEDULE_NODE_HELPER_H

#include <cstdint>
#include <memory>
#include <optional>

#include "hdi_wrapper.h"
#include "schedule_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ScheduleNodeHelper {
public:
    using HdiScheduleInfo = OHOS::HDI::UserAuth::V1_0::ScheduleInfo;
    struct NodeOptionalPara {
        std::optional<uint32_t> expire;
        std::optional<uint32_t> tokenId;
        std::optional<PinSubType> pinSubType;
    };

    static bool BuildFromHdi(const std::vector<HdiScheduleInfo> &infos, std::shared_ptr<ScheduleNodeCallback> callback,
        std::vector<std::shared_ptr<ScheduleNode>> &nodes);
    static bool BuildFromHdi(const std::vector<HdiScheduleInfo> &infos, std::shared_ptr<ScheduleNodeCallback> callback,
        std::vector<std::shared_ptr<ScheduleNode>> &nodes, const NodeOptionalPara &para);

private:
    static bool ScheduleInfoToScheduleNode(const HdiScheduleInfo &info, std::shared_ptr<ScheduleNode> &node,
        const NodeOptionalPara &para, const std::shared_ptr<ScheduleNodeCallback> &callback = nullptr);

    static bool ScheduleInfoToExecutors(const HdiScheduleInfo &info, std::shared_ptr<ResourceNode> &collector,
        std::shared_ptr<ResourceNode> &verifier);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SCHEDULE_NODE_HELPER_H