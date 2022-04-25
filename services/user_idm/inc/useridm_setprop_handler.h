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

#ifndef USERIDM_SET_PROP_HANDLER_H
#define USERIDM_SET_PROP_HANDLER_H

#include "iuseridm_callback.h"
#include "useridm_module.h"
#include "set_prop_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
class UserIDMSetPropHandler : public CoAuth::SetPropCallback {
public:
    UserIDMSetPropHandler(AuthType type, const uint64_t challenge, const  uint64_t sessionId, uint64_t credentialId,
        const std::shared_ptr<UserIDMModule>& data, const sptr<IIDMCallback>& callback);
    virtual ~UserIDMSetPropHandler() = default;

    void OnResult(uint32_t result, std::vector<uint8_t>& extraInfo) override;
    void ResetCallback();

private:
    uint64_t lastChallenge_;
    uint64_t lastScheduleId_;
    uint64_t lastCredentialId_;
    std::shared_ptr<UserIDMModule> propDataCallback_;
    sptr<IIDMCallback> propInnerCallback_;
    AuthType type_; // 0: add cred 1: modify cred
    std::mutex mutex_;
};
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS
#endif // USERIDM_SET_PROP_HANDLER_PROXY_H
