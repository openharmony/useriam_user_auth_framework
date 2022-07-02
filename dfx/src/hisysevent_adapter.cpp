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

#include "hisysevent_adapter.h"

#include <cinttypes>

#include "hisysevent.h"
#include "iam_logger.h"

#define LOG_LABEL Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
using HiSysEventNameSpace = OHOS::HiviewDFX::HiSysEvent;
const std::string DOMAIN_STR = std::string(HiSysEventNameSpace::Domain::USERIAM_FWK);

void ReportSystemFault(const std::string &timeString, const std::string &moudleName)
{
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "USERIAM_SYSTEM_FAULT",
        HiSysEventNameSpace::EventType::FAULT,
        "HAPPEN_TIME", timeString,
        "MODULE_NAME", moudleName);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, timeString %{public}s, moudleName %{public}s.",
            ret, timeString.c_str(), moudleName.c_str());
    }
}

void ReportTemplateChange(int32_t executorType, uint32_t changeType, const std::string &reason)
{
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "USERIAM_TEMPLATE_CHANGE",
        HiSysEventNameSpace::EventType::SECURITY,
        "EXECUTOR_TYPE", executorType,
        "CHANGE_TYPE", changeType,
        "TRIGGER_REASON", reason);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, executorType %{public}d,"
            "changeType %{public}d, trigger reason %{public}s.",
            ret, executorType, changeType, reason.c_str());
    }
}
void ReportBehaviorCredChange(uint32_t userId, uint32_t authType, uint32_t operationType, uint32_t optResult)
{
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "USERIAM_USER_CREDENTIAL_MANAGER",
        HiSysEventNameSpace::EventType::BEHAVIOR,
        "USER_ID", userId,
        "AUTH_TYPE", authType,
        "OPERATION_TYPE", operationType,
        "OPERATION_RESULT", optResult);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, userId %{public}d, authType %{public}d,"
            "operationType %{public}d, optResult %{public}d.",
            ret, userId, authType, operationType, optResult);
    }
}

void ReportSecurityCredChange(uint32_t userId, uint32_t authType, uint32_t operationType, uint32_t optResult)
{
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "USERIAM_CREDENTIAL_CHANGE",
        HiSysEventNameSpace::EventType::SECURITY,
        "USER_ID", userId,
        "AUTH_TYPE", authType,
        "OPERATION_TYPE", operationType,
        "OPERATION_RESULT", optResult);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, userId %{public}d, authType %{public}d,"
            "operationType %{public}d, optResult %{public}d.",
            ret, userId, authType, operationType, optResult);
    }
}

void ReportUserAuth(const UserAuthInfo &info)
{
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "USERIAM_USER_AUTH",
        HiSysEventNameSpace::EventType::BEHAVIOR,
        "CALLING_ID", info.callingUid,
        "AUTH_TYPE", info.authType,
        "AUTH_TRUST_LEVEL", info.atl,
        "AUTH_RESULT", info.authResult,
        "AUTH_TIME_SPAN", info.timeSpanString,
        "SDK_VERSION", info.sdkVersion);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, callingUid %{public}"  PRIu64 ", authType %{public}d,"
            "atl %{public}d, authResult %{public}d, timeSpanString %{public}s, sdkVersion%{public}d.",
            ret, info.callingUid, info.authType, info.atl, info.authResult,
            info.timeSpanString.c_str(), info.sdkVersion);
    }
}

void ReportPinAuth(const PinAuthInfo &info)
{
    int ret = HiSysEventNameSpace::Write(DOMAIN_STR, "USERIAM_PIN_AUTH",
        HiSysEventNameSpace::EventType::SECURITY,
        "USER_ID", info.userId,
        "CALLING_ID", info.callingUid,
        "AUTH_TIME", info.authTimeString,
        "AUTH_RESULT", info.authResult,
        "REMAIN_TIME", info.remainTime,
        "FREEXING_TIME", info.freezingTime);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, userId %{public}d, callingUid %{public}" PRIu64
            ",authTimeString %{public}s, authResult %{public}d, remainTime %{public}d, freezingTime%{public}d.",
            ret, info.userId, info.callingUid, info.authTimeString.c_str(), info.authResult,
            info.remainTime, info.freezingTime);
    }
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS