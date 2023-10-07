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

#include "trace.h"

#include <sstream>
#include "iam_logger.h"
#include "iam_time.h"
#include "hisysevent_adapter.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
Trace Trace::trace;

Trace::Trace()
{
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessCredChangeEvent);
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessUserAuthEvent);
}

Trace::~Trace()
{
}

void Trace::ProcessCredChangeEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    bool checkRet = metaData.operationType == TRACE_ADD_CREDENTIAL ||
        metaData.operationType == TRACE_DELETE_CREDENTIAL ||
        metaData.operationType == TRACE_UPDATE_CREDENTIAL ||
        metaData.operationType == TRACE_GET_CREDENTIAL ||
        metaData.operationType == TRACE_DELETE_USER ||
        metaData.operationType == TRACE_ENFORCE_DELETE_USER;
    if (!checkRet) {
        return;
    }
    int32_t userId = 0;
    int32_t authType = 0;
    uint32_t operationType = metaData.operationType;
    uint32_t optResult = 0;
    std::string bundleName = "";
    uint64_t contextId = 0;
    if (metaData.userId.has_value()) {
        userId = metaData.userId.value();
    }
    if (metaData.authType.has_value()) {
        authType = metaData.authType.value();
    }
    if (metaData.operationResult) {
        optResult = metaData.operationResult;
    }
    if (metaData.bundleName.has_value()) {
        bundleName = metaData.bundleName.value();
    }
    if (metaData.contextId.has_value()) {
        contextId = metaData.contextId.value();
    }
    uint64_t timeSpan = std::chrono::duration_cast<std::chrono::milliseconds>(metaData.endTime - metaData.startTime).count();
    std::ostringstream ss;
    ss << timeSpan << " ms";
    std::string timeSpanString = ss.str();
    ReportBehaviorCredChange(userId, authType, operationType, optResult, bundleName);
    if (metaData.operationType != TRACE_GET_CREDENTIAL) {
        ReportSecurityCredChange(userId, authType, operationType, optResult, bundleName, contextId, timeSpan);
    }
    IAM_LOGI("start to process cred change event");
}

void Trace::ProcessUserAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    using namespace std::chrono;
    bool checkRet = metaData.operationType == TRACE_AUTH_USER &&
        (metaData.authType.has_value() || metaData.authWidgetType.has_value());
    if (!checkRet) {
        return;
    }
    UserAuthInfo info = {};
    if (metaData.callingUid.has_value()) {
        info.callingUid = metaData.callingUid.value();
    }
    if (metaData.authType.has_value()) {
        info.authType = metaData.authType.value();
    }
    if (metaData.authWidgetType.has_value()) {
        info.authWidgetType = metaData.authWidgetType.value();
    }
    if (metaData.atl.has_value()) {
        info.atl = metaData.atl.value();
    }
    if (metaData.operationResult) {
        info.authResult = metaData.operationResult;
    }
    if (metaData.bundleName.has_value()) {
        info.bundleName = metaData.bundleName.value();
    }
    auto timeSpan = duration_cast<milliseconds>(metaData.endTime - metaData.startTime);
    std::ostringstream ss;
    ss << timeSpan.count() << " ms";
    info.timeSpanString = ss.str();
    if (metaData.sdkVersion.has_value()) {
        info.sdkVersion = metaData.sdkVersion.value();
    }

    ReportUserAuth(info);
    IAM_LOGI("start to process user auth event");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS