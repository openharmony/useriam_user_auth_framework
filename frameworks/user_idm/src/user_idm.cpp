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

#include "user_idm.h"
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
uint64_t UserIDM::OpenSession(const int32_t userId)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "OpenSession start with userid: %{public}d", userId);
    return 0;
}

void UserIDM::CloseSession(const int32_t userId)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "CloseSession start with userid: %{public}d", userId);
}

void UserIDM::AddCredential(const int32_t userId, const AddCredInfo& credInfo,
    const std::shared_ptr<IDMCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "AddCredential start with userid: %{public}d", userId);
}

void UserIDM::UpdateCredential(const int32_t userId, const AddCredInfo& credInfo,
    const std::shared_ptr<IDMCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "UpdateCredential start with userid: %{public}d", userId);
}

int32_t UserIDM::Cancel(const int32_t userId)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "Cancel start with userid: %{public}d", userId);
    return 0;
}


void UserIDM::DelUser(const int32_t userId, const std::vector<uint8_t> authToken,
    const std::shared_ptr<IDMCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "DelUser start with userid: %{public}d", userId);
}

void UserIDM::DelCredential(const int32_t userId, const uint64_t credentialId,
    const std::vector<uint8_t> authToken, const std::shared_ptr<IDMCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "DelCred start with userid: %{public}d", userId);
}

int32_t UserIDM::GetAuthInfo(int32_t userId, AuthType authType, const std::shared_ptr<GetInfoCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "GetAuthInfo start with userid: %{public}d", userId);
    return 0;
}

int32_t UserIDM::GetSecInfo(const int32_t userId, const std::shared_ptr<GetSecInfoCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "GetSecInfo start with userid: %{public}d", userId);
    return 0;
}

int32_t UserIDM::EnforceDelUser(const int32_t userId, const std::shared_ptr<IDMCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_INNERAPI, "EnforceDelUser start with userid: %{public}d", userId);
    return 0;
}
} // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS