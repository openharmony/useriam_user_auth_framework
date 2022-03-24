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

#include "auth_attributes.h"

#include <mutex>

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
    void GetPropAuthInfo(int32_t userId, uint64_t callerUid, std::string pkgName, GetPropertyRequest request,
        sptr<IUserAuthCallback> &callback);
    void CoAuthSetPropAuthInfo(CallerInfo callerInfo, int32_t resultCode, UserAuthToken authToken,
        SetPropertyRequest request);
    void SetPropAuthInfo(CallerInfo callerInfo, int32_t resultCode, UserAuthToken authToken, SetPropertyRequest request,
        std::vector<uint64_t> templateIds);
    void GetPropAuthInfoCoAuth(CallerInfo callerInfo, int32_t resultCode, UserAuthToken authToken,
        GetPropertyRequest request, sptr<IUserAuthCallback> &callback);
    int32_t GenerateSolution(AuthSolution param, std::vector<uint64_t> &sessionIds);
    int32_t RequestAuthResult(uint64_t contextId, std::vector<uint8_t> scheduleToken, UserAuthToken &authToken,
        std::vector<uint64_t> &sessionIds);
    int32_t CancelContext(uint64_t contextId, std::vector<uint64_t> &sessionIds);
    int32_t Cancel(uint64_t sessionId);
    int32_t GetExecutorProp(uint64_t callerUid, std::string pkgName, uint64_t templateId, GetPropertyRequest request,
        ExecutorProperty &result);
    int32_t SetExecutorProp(uint64_t callerUid, std::string pkgName, SetPropertyRequest request,
        sptr<IUserAuthCallback> &callback);
    int32_t GetVersion();
    int32_t CoAuth(CoAuthInfo coAuthInfo, sptr<IUserAuthCallback> &callback);

private:
    UserAuthAdapter() = default;
    ~UserAuthAdapter() = default;
    int32_t GetEachExecutorProp(GetPropertyRequest &request, ExecutorProperty &result, uint32_t &value,
        std::shared_ptr<OHOS::UserIAM::AuthResPool::AuthAttributes> pAuthAttributes);
    int32_t SetProPropAuthInfo(OHOS::UserIAM::AuthResPool::AuthAttributes &authAttributes, CallerInfo callerInfo,
        SetPropertyRequest request, std::vector<uint64_t> templateIds,
        std::shared_ptr<CoAuth::SetPropCallback> &setPropCallback);
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // USERAUTH_ADAPTER_H
