/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_USERIAM_DFX_HISYSEVENT_ADAPTER_H
#define OHOS_USERIAM_DFX_HISYSEVENT_ADAPTER_H

#include <string>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
struct UserAuthTrace {
    std::string callerName;
    uint32_t sdkVersion = 0;
    uint32_t atl = 0;
    int32_t authType = 0;
    int32_t authResult = -1;
    uint64_t timeSpan = 0;
    uint32_t authWidgetType = 0;
    int32_t userId = 0;
    int32_t callerType = 0;
    uint32_t reuseUnlockResultMode = 0;
    uint64_t reuseUnlockResultDuration = 0;
};

struct UserAuthFwkTrace {
    std::string callerName;
    uint64_t requestContextId = 0;
    uint64_t authContextId = 0;
    uint32_t atl = 0;
    int32_t authType = 0;
    int32_t authResult = -1;
    uint64_t timeSpan = 0;
};

struct UserCredManagerTrace {
    std::string callerName;
    int32_t userId = 0;
    int32_t authType = 0;
    uint32_t operationType = 0;
    int32_t operationResult = -1;
};

struct UserCredChangeTrace {
    std::string callerName;
    uint64_t requestContextId = 0;
    int32_t userId = 0;
    int32_t authType = 0;
    uint32_t operationType = 0;
    int32_t operationResult = -1;
    uint64_t timeSpan = 0;
};

struct TemplateChangeTrace {
    uint64_t scheduleId = 0;
    int32_t executorType = 0;
    uint32_t changeType = 0;
    std::string reason;
};

void ReportSystemFault(const std::string &timeString, const std::string &moudleName);
void ReportSecurityTemplateChange(const TemplateChangeTrace &info);
void ReportBehaviorCredManager(const UserCredManagerTrace &info);
void ReportSecurityCredChange(const UserCredChangeTrace &info);
void ReportUserAuth(const UserAuthTrace &info);
void ReportSecurityUserAuthFwk(const UserAuthFwkTrace &info);
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // OHOS_USERIAM_DFX_HISYSEVENT_ADAPTER_H