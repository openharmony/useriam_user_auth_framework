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

namespace OHOS {
namespace UserIam {
namespace UserAuth {

void PublishEventAdapter::PublishDeletedEvent(int32_t userId)
{
    (void)userId;
}

void PublishEventAdapter::PublishCreatedEvent(int32_t userId, uint64_t scheduleId)
{
    (void)userId;
    (void)scheduleId;
}

void PublishEventAdapter::PublishUpdatedEvent(int32_t userId, uint64_t scheduleId)
{
    (void)userId;
    (void)scheduleId;
}

void PublishEventAdapter::PublishCredentialUpdatedEvent(int32_t userId, int32_t authType, uint32_t credentialCount)
{
    (void)userId;
    (void)authType;
    (void)credentialCount;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS