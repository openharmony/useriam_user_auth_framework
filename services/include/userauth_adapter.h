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

#ifndef USERAUTH_ADAPTER_H
#define USERAUTH_ADAPTER_H

#include <mutex>
#include "auth_attributes.h"
#include "co_auth.h"
#include "context_thread_pool.h"
#include "iuserauth_callback.h"
#include "set_prop_callback.h"
#include "userauth_info.h"
#include "userauth_interface.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuthAdapter {
public:
    static UserAuthAdapter &GetInstance();
    int32_t GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t &authTrustLevel);

    /* Get the executor authentication properties */
    void GetPropAuthInfo(int32_t userID, uint64_t callerUID, std::string pkgName, GetPropertyRequest requset,
        sptr<IUserAuthCallback> &callback);

    /** This method is called to set the executor properties
     *  after the callback of the coAuth is called to obtain the scheduling token
     *  and the authentication result is successful.
     * */
    void CoauthSetPropAuthInfo(CallerInfo callerInfo, int32_t resultCode,
        UserAuthToken authToken, SetPropertyRequest requset);

    /* Set the executor authentication properties for freez or unfreez */
    void SetPropAuthInfo(CallerInfo callerInfo, int32_t resultCode, UserAuthToken authToken,
        SetPropertyRequest requset, std::vector<uint64_t> templateIds);
    /* get the executor authentication properties for Coauth */
    void GetPropAuthInfoCoauth(CallerInfo callerInfo, int32_t resultCode,
        UserAuthToken authToken, GetPropertyRequest requset, sptr<IUserAuthCallback> &callback);
    int32_t GenerateSolution(AuthSolution param, std::vector<uint64_t> &sessionIds);
    int32_t RequestAuthResult(uint64_t contextId, std::vector<uint8_t> scheduleToken, UserAuthToken &authToken,
        std::vector<uint64_t> &sessionIds);
    int32_t CancelContext(uint64_t contextId, std::vector<uint64_t> &sessionIds);
    int32_t Cancel(uint64_t sessionId);
    /* get the executor authentication properties */
    int32_t GetExecutorProp(uint64_t callerUID, std::string pkgName, uint64_t templateId, GetPropertyRequest requset,
        ExecutorProperty &result);
    /* Set the executor authentication properties */
    int32_t SetExecutorProp(uint64_t callerUID, std::string pkgName, SetPropertyRequest requset,
        sptr<IUserAuthCallback> &callback);
    int32_t GetVersion();
    int32_t coAuth(CoAuthInfo coAuthInfo, sptr<IUserAuthCallback> &callback);

private:
    UserAuthAdapter() = default;
    ~UserAuthAdapter() = default;
    int32_t GetEachExecutorProp(GetPropertyRequest &requset, ExecutorProperty &result, uint32_t &value,
        std::shared_ptr<OHOS::UserIAM::AuthResPool::AuthAttributes> pAuthAttributes);
    int32_t SetProPropAuthInfo(OHOS::UserIAM::AuthResPool::AuthAttributes &authAttributes, CallerInfo callerInfo,
        SetPropertyRequest requset, std::vector<uint64_t> templateIds,
        std::shared_ptr<CoAuth::SetPropCallback> &setPropCallback);
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // USERAUTH_ADAPTER_H
