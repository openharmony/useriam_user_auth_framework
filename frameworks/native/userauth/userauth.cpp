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

#include "userauth.h"
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>
#include "user_auth.h"
#include "system_ability_definition.h"
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
UserAuth::UserAuth() = default;
UserAuth::~UserAuth() = default;

void UserAuth::GetProperty(const int32_t userId, const GetPropertyRequest &request,
    std::shared_ptr<GetPropCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "GetProperty start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERAPI, "GetProperty callback is nullptr");
        return;
    }
    USERAUTH_HILOGI(MODULE_INNERAPI, "GetProperty start with userid: %{public}d", userId);
    UserAuthNative::GetInstance().GetProperty(userId, request, callback);
}

void UserAuth::SetProperty(const int32_t userId, const SetPropertyRequest &request,
    std::shared_ptr<SetPropCallback> callback)
{
    static_cast<void>(userId);
    USERAUTH_HILOGD(MODULE_INNERAPI, "SetProperty start");
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERAPI, "SetProperty callback is nullptr");
        return;
    }
    USERAUTH_HILOGI(MODULE_INNERAPI, "SetProperty start with userid: %{public}d", userId);
    UserAuthNative::GetInstance().SetProperty(request, callback);
}

uint64_t UserAuth::AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
    const AuthTrustLevel authTrustLevel, std::shared_ptr<UserAuthCallback> callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "AuthUser start with userid: %{public}d", userId);
    if (callback == nullptr) {
        USERAUTH_HILOGE(MODULE_INNERAPI, "AuthUser callback is nullptr");
        return INVALID_PARAMETERS;
    }
    uint64_t ret = UserAuthNative::GetInstance().AuthUser(userId, challenge, authType, authTrustLevel, callback);
    return ret;
}

int32_t UserAuth::CancelAuth(const uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "CancelAuth start");
    uint32_t ret = UserAuthNative::GetInstance().CancelAuth(contextId);
    return ret;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
