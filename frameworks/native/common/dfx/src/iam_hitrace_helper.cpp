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

#include "iam_hitrace_helper.h"

#include <atomic>

#include "hitrace_meter.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
IamHitraceHelper::IamHitraceHelper(std::string value)
    : taskId_(GetHiTraceTaskId()),
      value_(std::move(value))
{
    StartAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_USERIAM, value_.c_str(), taskId_, "");
}

IamHitraceHelper::~IamHitraceHelper()
{
    FinishAsyncTraceEx(HITRACE_LEVEL_INFO, HITRACE_TAG_USERIAM, value_.c_str(), taskId_);
}

int32_t IamHitraceHelper::GetHiTraceTaskId()
{
    static std::atomic<int32_t> taskId(0);
    return taskId++;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS