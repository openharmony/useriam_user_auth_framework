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
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessPinAuthEvent);
    ContextCallbackNotifyListener::GetInstance().AddNotifier(ProcessDelUserEvent);
}

Trace::~Trace()
{
}

void Trace::ProcessCredChangeEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    bool checkRet = metaData.operationType == TRACE_ADD_CREDENTIAL ||
        metaData.operationType == TRACE_DELETE_CREDENTIAL ||
        metaData.operationType == TRACE_UPDATE_CREDENTIAL;
    if (!checkRet) {
        return;
    }
    int32_t userId = 0;
    int32_t authType = 0;
    uint32_t operationType = metaData.operationType;
    uint32_t optResult = 0;
    if (metaData.userId.has_value()) {
        userId = metaData.userId.value();
    }
    if (metaData.authType.has_value()) {
        authType = metaData.authType.value();
    }
    if (metaData.operationResult) {
        optResult = metaData.operationResult;
    }
    ReportBehaviorCredChange(userId, authType, operationType, optResult);
    ReportSecurityCredChange(userId, authType, operationType, optResult);
    IAM_LOGI("start to process cred change event");
}

void Trace::ProcessUserAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    using namespace std::chrono;
    bool checkRet = metaData.operationType == TRACE_AUTH_USER && metaData.authType.has_value();
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
    if (metaData.atl.has_value()) {
        info.atl = metaData.atl.value();
    }
    if (metaData.operationResult) {
        info.authResult = metaData.operationResult;
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

void Trace::ProcessPinAuthEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    bool checkRet = metaData.operationType == TRACE_AUTH_USER && metaData.authType.has_value() &&
        metaData.authType == PIN;
    if (!checkRet) {
        return;
    }
    PinAuthInfo info = {};
    if (metaData.userId.has_value()) {
        info.userId = metaData.userId.value();
    }
    if (metaData.callingUid.has_value()) {
        info.callingUid = metaData.callingUid.value();
    }
    info.authTimeString = Common::GetNowTimeString();
    if (metaData.operationResult) {
        info.authResult = metaData.operationResult;
    }
    if (metaData.remainTime.has_value()) {
        info.remainTime = metaData.remainTime.value();
    }
    if (metaData.freezingTime.has_value()) {
        info.freezingTime = metaData.freezingTime.value();
    }
    ReportPinAuth(info);
    IAM_LOGI("start to process pin auth event");
}

void Trace::ProcessDelUserEvent(const ContextCallbackNotifyListener::MetaData &metaData)
{
    OperationType type = metaData.operationType;
    bool checkRet = type == TRACE_DELETE_USER || type == TRACE_ENFORCE_DELETE_USER;
    if (!checkRet) {
        return;
    }
    IAM_LOGI("start to process del user event");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS