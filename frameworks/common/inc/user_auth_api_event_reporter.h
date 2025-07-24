/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_API_EVENT_REPORTER_H
#define USER_AUTH_API_EVENT_REPORTER_H

#include <cstdint>
#include <mutex>
#include <string>

#include "nocopyable.h"

#include "auth_common.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthApiEventReporter : public NoCopyable {
public:
    UserAuthApiEventReporter(std::string apiName);
    ~UserAuthApiEventReporter() = default;

    void ReportSuccess();
    void ReportFailed(UserAuthResultCode resultCode);
    void ReportFailed(int32_t resultCode);

private:
    static int64_t GetProcessorId();

    void Report(int32_t result, int32_t errCode);

    static int64_t processorId_;

    bool isReported_ = false;
    std::string transId_;
    std::string apiName_;
    int64_t beginTime_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_API_EVENT_REPORTER_H