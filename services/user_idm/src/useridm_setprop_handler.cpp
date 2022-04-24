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

#include "useridm_setprop_handler.h"
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
UserIDMSetPropHandler::UserIDMSetPropHandler(AuthType type, const uint64_t challenge, const uint64_t sessionId,
    uint64_t credentialId, const std::shared_ptr<UserIDMModule>& data, const sptr<IIDMCallback>& callback)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMSetPropHandler constructor start");

    type_ = type;
    lastChallenge_ = challenge;
    lastScheduleId_ = sessionId;
    lastCredentialId_ = credentialId;
    propDataCallback_ = data;
    propInnerCallback_ = callback;

    if (propInnerCallback_ == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "sorry: input callback is nullptr");
    }
}

void UserIDMSetPropHandler::OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMSetPropHandler OnResult start: %{public}u, %{public}d", result, type_);
    std::lock_guard<std::mutex> lock(mutex_);
    if ((type_ == PIN) || (type_ == FACE)) {
        if (propInnerCallback_ != nullptr) {
            USERIDM_HILOGI(MODULE_SERVICE, "ready to call callback");
            RequestResult reqResult;
            reqResult.credentialId = lastCredentialId_;
            propInnerCallback_->OnResult(result, reqResult);
        } else {
            USERIDM_HILOGE(MODULE_SERVICE, "propInnerCallback_ is nullptr");
        }
        propDataCallback_->DeleteSessionId(); // no need to check session
    }
}

void UserIDMSetPropHandler::ResetCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    propDataCallback_ = nullptr;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
