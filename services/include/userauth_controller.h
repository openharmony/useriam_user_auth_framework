/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef USERAUTH_CONTROLLER_H
#define USERAUTH_CONTROLLER_H

#include "userauth_info.h"
#include "userauth_adapter.h"
#include "iuserauth_callback.h"
#include "userauth_interface.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuthController {
public:
    int32_t GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t &authTrustLevel);
    void GetPropAuthInfo(std::string pkgName, uint64_t callerUID, GetPropertyRequest getPropertyRequest,
                         sptr<IUserAuthCallback>& callback);
    int32_t SetExecutorProp(uint64_t callerUID, std::string pkgName, SetPropertyRequest setPropertyrequest,
                            sptr<IUserAuthCallback>& callback);
    int32_t GetUserID(int32_t &userID);
    int32_t GetCallerUid(uint64_t &callerUID);
    int32_t GetPkgName(std::string &pkgName);
    int32_t AddContextID(uint64_t contextID);
    int32_t IsContextIDExist(uint64_t contextID);
    int32_t GenerateContextID(uint64_t &contextID);
    int32_t DeleteContextID(uint64_t contextID);
    int32_t GenerateSolution(AuthSolution param, std::vector<uint64_t> &sessionIds);
    int32_t coAuth(CoAuthInfo coAuthInfo, sptr<IUserAuthCallback>& callback);
    int32_t CancelContext(uint64_t contextId, std::vector<uint64_t> &sessionIds);
    int32_t Cancel(uint64_t sessionId);
    int32_t GetVersion();
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USERAUTH_CONTROLLER_H
