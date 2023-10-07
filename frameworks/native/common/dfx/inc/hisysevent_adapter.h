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
struct UserAuthInfo {
    uint64_t callingUid = 0;
    int32_t authType = 0;
    uint32_t atl = 0;
    uint32_t authResult = 0;
    std::string timeSpanString;
    uint32_t sdkVersion = 0;
    uint32_t authWidgetType = 0;
    std::string bundleName;
};

void ReportSystemFault(const std::string &timeString, const std::string &moudleName);
void ReportTemplateChange(int32_t executorType, uint32_t changeType, const std::string &reason);
void ReportBehaviorCredChange(int32_t userId, int32_t authType, uint32_t operationType, uint32_t optResult,
    std::string bundleName);
void ReportSecurityCredChange(int32_t userId, int32_t authType, uint32_t operationType, uint32_t optResult,
    std::string bundleName, uint64_t contextId, uint64_t consumingTime);
void ReportUserAuth(const UserAuthInfo &info);
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // OHOS_USERIAM_DFX_HISYSEVENT_ADAPTER_H