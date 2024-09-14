/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "publish_event_adapter.h"

#include "common_event_manager.h"
#include "iam_logger.h"

#ifndef LOG_LABEL
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const std::string TAG_USERID = "userId";
const std::string TAG_AUTHTYPE = "authType";
const std::string TAG_CREDENTIALCOUNT = "credentialCount";
const std::string TAG_SCHEDULEID = "scheduleId";
const std::string USER_PIN_CREATED_EVENT = "USER_PIN_CREATED_EVENT";
const std::string USER_PIN_DELETED_EVENT = "USER_PIN_DELETED_EVENT";
const std::string USER_PIN_UPDATED_EVENT = "USER_PIN_UPDATED_EVENT";
const std::string USER_CREDENTIAL_UPDATED_EVENT = "USER_CREDENTIAL_UPDATED_EVENT";

void PublishEvent(EventFwk::CommonEventData data)
{
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(false);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(data, publishInfo)) {
        IAM_LOGE("PublishCommonEvent failed, eventAction is %{public}s", data.GetWant().GetAction().c_str());
        return;
    }
    IAM_LOGI("PublishCommonEvent succeed, eventAction is %{public}s", data.GetWant().GetAction().c_str());
}
} // namespace

void PublishEventAdapter::PublishDeletedEvent(int32_t userId)
{
    EventFwk::Want want;
    want.SetAction(USER_PIN_DELETED_EVENT);
    EventFwk::CommonEventData data(want);
    data.SetCode(userId);
    PublishEvent(data);
    return;
}

void PublishEventAdapter::PublishCreatedEvent(int32_t userId, uint64_t scheduleId)
{
    if (scheduleId == 0) {
        IAM_LOGE("Bad Parameter!");
        return;
    }
    EventFwk::Want want;
    want.SetAction(USER_PIN_CREATED_EVENT);
    want.SetParam(TAG_SCHEDULEID, std::to_string(scheduleId));
    EventFwk::CommonEventData data(want);
    data.SetCode(userId);
    PublishEvent(data);
    return;
}

void PublishEventAdapter::PublishUpdatedEvent(int32_t userId, uint64_t scheduleId)
{
    if (scheduleId == 0) {
        IAM_LOGE("Bad Parameter!");
        return;
    }
    EventFwk::Want want;
    want.SetAction(USER_PIN_UPDATED_EVENT);
    want.SetParam(TAG_SCHEDULEID, std::to_string(scheduleId));
    EventFwk::CommonEventData data(want);
    data.SetCode(userId);
    PublishEvent(data);
    return;
}

void PublishEventAdapter::PublishCredentialUpdatedEvent(int32_t userId, int32_t authType, uint32_t credentialCount)
{
    EventFwk::Want want;
    want.SetAction(USER_CREDENTIAL_UPDATED_EVENT);
    want.SetParam(TAG_USERID, std::to_string(userId));
    want.SetParam(TAG_AUTHTYPE, std::to_string(authType));
    want.SetParam(TAG_CREDENTIALCOUNT, std::to_string(credentialCount));
    EventFwk::CommonEventData data(want);
    data.SetCode(0);
    PublishEvent(data);
    IAM_LOGI("PublishCredentialUpdatedEvent, userId: %{public}d, authType: %{public}d, credentialCount: %{public}u",
        userId, authType, credentialCount);
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif