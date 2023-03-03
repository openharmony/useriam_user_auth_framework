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

#ifndef ENROLL_COMMAND_H
#define ENROLL_COMMAND_H

#include "iam_hitrace_helper.h"

#include "async_command_base.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class EnrollCommand : public AsyncCommandBase {
public:
    EnrollCommand(std::weak_ptr<Executor> executor, uint64_t scheduleId, const Attributes &commandAttrs,
        std::shared_ptr<ExecutorMessenger> executorMessenger);
    ~EnrollCommand() override = default;

protected:
    ResultCode SendRequest() override;
    void OnAcquireInfoInner(int32_t acquire, const std::vector<uint8_t> &extraInfo) override;
    void OnResultInner(ResultCode result, const std::vector<uint8_t> &extraInfo) override;

private:
    uint32_t transNum_ = 1;
    std::shared_ptr<Attributes> attributes_;
    std::shared_ptr<IamHitraceHelper> iamHitraceHelper_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // ENROLL_COMMAND_H