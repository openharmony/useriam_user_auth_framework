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

#ifndef IAM_SCHEDULE_CALLBACK_H
#define IAM_SCHEDULE_CALLBACK_H

#include <cstdint>
#include <memory>
#include <vector>

#include "attributes.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ScheduleNodeCallback {
public:
    virtual ~ScheduleNodeCallback() = default;
    virtual void OnScheduleStarted() = 0;
    virtual void OnScheduleProcessed(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg) = 0;
    virtual void OnScheduleStoped(int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SCHEDULE_CALLBACK_H