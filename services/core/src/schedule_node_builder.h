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

#ifndef IAM_SCHEDULE_NODE_BUILDER_H
#define IAM_SCHEDULE_NODE_BUILDER_H

#include <cstdint>
#include <memory>

#include "resource_node.h"
#include "schedule_node_impl.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ScheduleNodeBuilder final : public ScheduleNode::Builder,
                                  public std::enable_shared_from_this<ScheduleNodeBuilder>,
                                  public NoCopyable {
public:
    ScheduleNodeBuilder(const std::shared_ptr<ResourceNode> &collector, const std::shared_ptr<ResourceNode> &verifier);
    ~ScheduleNodeBuilder() override = default;
    std::shared_ptr<Builder> SetScheduleId(uint64_t scheduleId) override;
    std::shared_ptr<Builder> SetAccessTokenId(uint32_t tokenId) override;
    std::shared_ptr<Builder> SetPinSubType(PinSubType pinSubType) override;
    std::shared_ptr<Builder> SetTemplateIdList(const std::vector<uint64_t> &templateIdList) override;
    std::shared_ptr<Builder> SetAuthType(AuthType authType) override;
    std::shared_ptr<Builder> SetExecutorMatcher(uint32_t executorMatcher) override;
    std::shared_ptr<Builder> SetScheduleMode(ScheduleMode scheduleMode) override;
    std::shared_ptr<Builder> SetScheduleCallback(const std::shared_ptr<ScheduleNodeCallback> &callback) override;
    std::shared_ptr<Builder> SetExpiredTime(uint32_t ms) override;
    std::shared_ptr<Builder> SetParametersAttributes(const std::shared_ptr<Attributes> &parameters) override;
    std::shared_ptr<Builder> SetThreadHandler(const std::shared_ptr<ThreadHandler> &threadHandler) override;

    std::shared_ptr<ScheduleNode> Build() override;

    static bool CheckExecutors(const std::shared_ptr<ResourceNode> &collector,
        const std::shared_ptr<ResourceNode> &verifier);

private:
    bool CheckParameters() const;

    const std::shared_ptr<ResourceNode> collector_;
    const std::shared_ptr<ResourceNode> verifier_;
    ScheduleNodeImpl::ScheduleInfo info_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SCHEDULE_NODE_BUILDER_H