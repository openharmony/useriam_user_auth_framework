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

#include "userauth_controller.h"
#include "userauth_datamgr.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
int32_t UserAuthController::GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t &authTrustLevel)
{
    return UserAuthAdapter::GetInstance().GetAuthTrustLevel(userId, authType, authTrustLevel);
}
int32_t UserAuthController::SetExecutorProp(uint64_t callerUID, std::string pkgName,
    SetPropertyRequest setPropertyrequest, sptr<IUserAuthCallback> &callback)
{
    return UserAuthAdapter::GetInstance().SetExecutorProp(callerUID, pkgName, setPropertyrequest, callback);
}
void UserAuthController::GetPropAuthInfo(int32_t userID, std::string pkgName, uint64_t callerUID,
    GetPropertyRequest getPropertyRequest, sptr<IUserAuthCallback> &callback)
{
    UserAuthAdapter::GetInstance().GetPropAuthInfo(userID, callerUID, pkgName, getPropertyRequest, callback);
}
int32_t UserAuthController::GenerateSolution(AuthSolution param, std::vector<uint64_t> &sessionIds)
{
    return UserAuthAdapter::GetInstance().GenerateSolution(param, sessionIds);
}
int32_t UserAuthController::coAuth(CoAuthInfo coAuthInfo, sptr<IUserAuthCallback> &callback)
{
    return UserAuthAdapter::GetInstance().coAuth(coAuthInfo, callback);
}
int32_t UserAuthController::CancelContext(uint64_t contextId, std::vector<uint64_t> &sessionIds)
{
    return UserAuthAdapter::GetInstance().CancelContext(contextId, sessionIds);
}
int32_t UserAuthController::Cancel(uint64_t sessionId)
{
    return UserAuthAdapter::GetInstance().Cancel(sessionId);
}
int32_t UserAuthController::AddContextID(uint64_t contextID)
{
    return UserAuthDataMgr::GetInstance().AddContextID(contextID);
}
int32_t UserAuthController::IsContextIDExist(uint64_t contextID)
{
    return UserAuthDataMgr::GetInstance().IsContextIDExist(contextID);
}
int32_t UserAuthController::GenerateContextID(uint64_t &contextID)
{
    return UserAuthDataMgr::GetInstance().GenerateContextID(contextID);
}
int32_t UserAuthController::DeleteContextID(uint64_t contextID)
{
    return UserAuthDataMgr::GetInstance().DeleteContextID(contextID);
}
int32_t UserAuthController::GetVersion()
{
    return UserAuthAdapter::GetInstance().GetVersion();
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
