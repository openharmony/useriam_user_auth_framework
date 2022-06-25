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
#ifndef IAM_MOCK_SCHEDULE_NODE_CALLBACK_H
#define IAM_MOCK_SCHEDULE_NODE_CALLBACK_H

#include <memory>

#include <gmock/gmock.h>

#include "schedule_node_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockScheduleNodeCallback final : public ScheduleNodeCallback {
public:
    MOCK_METHOD0(OnScheduleStarted, void());
    MOCK_METHOD3(OnScheduleProcessed,
        void(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg));
    MOCK_METHOD2(OnScheduleStoped, void(int32_t resultCode, const std::shared_ptr<Attributes> &finalResult));
    static std::shared_ptr<MockScheduleNodeCallback> Create()
    {
        using namespace testing;
        return std::make_shared<MockScheduleNodeCallback>();
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_SCHEDULE_NODE_CALLBACK_H