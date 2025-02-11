/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_SERVICE_STATUS_LISTENER_H
#define USER_AUTH_SERVICE_STATUS_LISTENER_H

#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthServicesStatusListener : public OHOS::SystemAbilityStatusChangeStub, public NoCopyable {
public:
    using AddFunc = std::function<void(void)>;
    using RemoveFunc = std::function<void(void)>;
    static sptr<UserAuthServicesStatusListener> Subscribe(
        std::string name, int32_t systemAbilityId, AddFunc addFunc, RemoveFunc removeFunc);

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    
private:
    UserAuthServicesStatusListener(std::string name, int32_t systemAbilityId, AddFunc addFunc, RemoveFunc removeFunc);
    ~UserAuthServicesStatusListener() override {};

    std::string name_;
    int32_t systemAbilityId_;
    AddFunc addFunc_;
    RemoveFunc removeFunc_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_SERVICE_STATUS_LISTENER_H
