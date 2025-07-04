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

#ifndef PUBLISH_EVENT_ADAPTER_H
#define PUBLISH_EVENT_ADAPTER_H

#include <mutex>
#include <string>
#include "user_idm_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class PublishEventAdapter {
public:
    static PublishEventAdapter &GetInstance();
    void PublishDeletedEvent(int32_t userId);
    void PublishCreatedEvent(int32_t userId, uint64_t scheduleId);
    void PublishUpdatedEvent(int32_t userId, uint64_t scheduleId);
    void PublishCredentialUpdatedEvent(int32_t userId, int32_t authType, uint32_t credentialCount);
    void CachePinUpdateParam(int32_t userId, uint64_t scheduleId, const CredChangeEventInfo &changeInfo);
    void CachePinUpdateParam(bool reEnrollFlag);
    void ClearPinUpdateCacheInfo();

private:
    PublishEventAdapter() = default;
    ~PublishEventAdapter() = default;

    std::mutex mutex_;
    int32_t userId_ {0};
    uint64_t scheduleId_ {0};
    CredChangeEventInfo credChangeEventInfo_ = {};
    bool reEnrollFlag_ {false};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif //PUBLISH_EVENT_ADAPTER_H