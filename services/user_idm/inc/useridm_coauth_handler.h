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

#ifndef USERIDM_COAUTH_HANDLER_PROXY_H
#define USERIDM_COAUTH_HANDLER_PROXY_H

#include "useridm_module.h"
#include "coauth_callback.h"
#include "useridm_setprop_handler.h"
#include "auth_info.h"
#include "co_auth.h"
#include "auth_attributes.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMCoAuthHandler : public CoAuth::CoAuthCallback {
public:
    explicit UserIDMCoAuthHandler(CoAuthType type, const uint64_t challenge, const uint64_t sessionId,
        const std::shared_ptr<UserIDMModule>& data, const sptr<IIDMCallback>& callback);
    virtual ~UserIDMCoAuthHandler() = default;

    void OnFinish(uint32_t resultCode, std::vector<uint8_t>& scheduleToken) override;
    void OnAcquireInfo(uint32_t acquire) override;
    void ResetCallback();

private:
    int32_t OnFinishModify(uint32_t resultCode, std::vector<uint8_t>& scheduleToken, uint64_t& credentialId);
    uint64_t lastChallenge_;
    uint64_t lastScheduleId_;
    std::shared_ptr<UserIDMModule> dataCallback_;
    sptr<IIDMCallback> innerCallback_;
    CoAuthType type_; // 0: add cred 1: modify cred
    std::mutex mutex_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
#endif // USERIDM_COAUTH_HANDLER_PROXY_H
