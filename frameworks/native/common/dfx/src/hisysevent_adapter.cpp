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

#include "hisysevent_adapter.h"

#include <cinttypes>

#include "hisysevent.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;

constexpr char STR_USER_ID[] = "USER_ID";
constexpr char STR_AUTH_TYPE[] = "AUTH_TYPE";
constexpr char STR_OPERATION_TYPE[] = "OPERATION_TYPE";
constexpr char STR_OPERATION_RESULT[] = "OPERATION_RESULT";
constexpr char STR_AUTH_RESULT[] = "AUTH_RESULT";
constexpr char STR_TRIGGER_REASON[] = "TRIGGER_REASON";
constexpr char STR_CHANGE_TYPE[] = "CHANGE_TYPE";
constexpr char STR_EXECUTOR_TYPE[] = "EXECUTOR_TYPE";
constexpr char STR_MODULE_NAME[] = "MODULE_NAME";
constexpr char STR_HAPPEN_TIME[] = "HAPPEN_TIME";
constexpr char STR_AUTH_TRUST_LEVEL[] = "AUTH_TRUST_LEVEL";
constexpr char STR_SDK_VERSION[] = "SDK_VERSION";
constexpr char STR_AUTH_WIDGET_TYPE[] = "AUTH_WIDGET_TYPE";
constexpr char STR_CALLER_NAME[] = "CALLER_NAME";
constexpr char STR_REQUEST_CONTEXTID[] = "REQUEST_CONTEXTID";
constexpr char STR_TIME_SPAN[] = "TIME_SPAN";
constexpr char STR_AUTH_CONTEXTID[] = "AUTH_CONTEXTID";
constexpr char STR_SCHEDULE_ID[] = "SCHEDULE_ID";
constexpr char STR_REUSE_UNLOCK_RESULT_TYPE[] = "REUSE_UNLOCK_RESULT_TYPE";
constexpr char STR_REUSE_UNLOCK_RESULT_DURATION[] = "REUSE_UNLOCK_RESULT_DURATION";

void ReportSystemFault(const std::string &timeString, const std::string &moudleName)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_SYSTEM_FAULT",
        HiSysEvent::EventType::FAULT,
        STR_HAPPEN_TIME, timeString,
        STR_MODULE_NAME, moudleName);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, timeString %{public}s, moudleName %{public}s.",
            ret, timeString.c_str(), moudleName.c_str());
    }
}

void ReportSecurityTemplateChange(const TemplateChangeTrace &info)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_TEMPLATE_CHANGE",
        HiSysEvent::EventType::SECURITY,
        STR_SCHEDULE_ID, info.scheduleId,
        STR_EXECUTOR_TYPE, info.executorType,
        STR_CHANGE_TYPE, info.changeType,
        STR_TRIGGER_REASON, info.reason);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, executorType %{public}d, changeType %{public}u,"
            "scheduleId %{public}s, trigger reason %{public}s.", ret, info.executorType, info.changeType,
            GET_MASKED_STRING(info.scheduleId).c_str(), info.reason.c_str());
    }
}

void ReportBehaviorCredManager(const UserCredManagerTrace &info)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_USER_CREDENTIAL_MANAGER",
        HiSysEvent::EventType::BEHAVIOR,
        STR_CALLER_NAME, info.callerName,
        STR_USER_ID, info.userId,
        STR_AUTH_TYPE, info.authType,
        STR_OPERATION_TYPE, info.operationType,
        STR_OPERATION_RESULT, info.operationResult);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, userId %{public}d, authType %{public}d,"
            "operationType %{public}u, operationResult %{public}d, callerName %{public}s.", ret, info.userId,
            info.authType, info.operationType, info.operationResult, info.callerName.c_str());
    }
}

void ReportSecurityCredChange(const UserCredChangeTrace &info)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_CREDENTIAL_CHANGE",
        HiSysEvent::EventType::SECURITY,
        STR_CALLER_NAME, info.callerName,
        STR_REQUEST_CONTEXTID, info.requestContextId,
        STR_USER_ID, info.userId,
        STR_AUTH_TYPE, info.authType,
        STR_OPERATION_TYPE, info.operationType,
        STR_OPERATION_RESULT, info.operationResult,
        STR_TIME_SPAN, info.timeSpan);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, userId %{public}d, authType %{public}d,"
            "operationType %{public}u, timeSpan %{public}" PRIu64 ", operationResult %{public}d, callerName %{public}s"
            ", requestContextId %{public}s.", ret, info.userId, info.authType, info.operationType, info.timeSpan,
            info.operationResult, info.callerName.c_str(),  GET_MASKED_STRING(info.requestContextId).c_str());
    }
}

void ReportUserAuth(const UserAuthTrace &info)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_USER_AUTH",
        HiSysEvent::EventType::BEHAVIOR,
        STR_CALLER_NAME, info.callerName,
        STR_SDK_VERSION, info.sdkVersion,
        STR_AUTH_TRUST_LEVEL, info.atl,
        STR_AUTH_TYPE, info.authType,
        STR_AUTH_RESULT, info.authResult,
        STR_TIME_SPAN, info.timeSpan,
        STR_AUTH_WIDGET_TYPE, info.authWidgetType,
        STR_REUSE_UNLOCK_RESULT_TYPE, info.reuseUnlockResultMode,
        STR_REUSE_UNLOCK_RESULT_DURATION, info.reuseUnlockResultDuration);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, authType %{public}d, atl %{public}u, authResult %{public}d"
            ", timeSpan %{public}" PRIu64 ", sdkVersion %{public}u, authwidgetType %{public}u, callerName %{public}s"
            ", reuseUnlockResultMode %{public}u, reuseUnlockResultDuration %{public}" PRIu64 ".",
            ret, info.authType, info.atl, info.authResult, info.timeSpan, info.sdkVersion, info.authWidgetType,
            info.callerName.c_str(), info.reuseUnlockResultMode, info.reuseUnlockResultDuration);
    }
}

void ReportSecurityUserAuthFwk(const UserAuthFwkTrace &info)
{
    int32_t ret = HiSysEventWrite(HiSysEvent::Domain::USERIAM_FWK, "USERIAM_USER_AUTH_FWK",
        HiSysEvent::EventType::SECURITY,
        STR_CALLER_NAME, info.callerName,
        STR_REQUEST_CONTEXTID, info.requestContextId,
        STR_AUTH_CONTEXTID, info.authContextId,
        STR_AUTH_TRUST_LEVEL, info.atl,
        STR_AUTH_TYPE, info.authType,
        STR_AUTH_RESULT, info.authResult,
        STR_TIME_SPAN, info.timeSpan);
    if (ret != 0) {
        IAM_LOGE("hisysevent write failed! ret %{public}d, authType %{public}d, atl %{public}u, authResult %{public}d,"
            "timeSpan %{public}" PRIu64 ", callerName %{public}s, requestContextId %{public}s, "
            "authContextId %{public}s.", ret, info.authType, info.atl, info.authResult, info.timeSpan,
            info.callerName.c_str(), GET_MASKED_STRING(info.requestContextId).c_str(),
            GET_MASKED_STRING(info.authContextId).c_str());
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS