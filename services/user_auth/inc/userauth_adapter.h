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

#include "v1_0/user_auth_interface_proxy.h"
#include "auth_attributes.h"
#include "coauth_manager.h"
#include "iuserauth_callback.h"
#include "set_prop_callback.h"
#include "userauth_info.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
struct AuthSolution {
    uint64_t contextId;
    int32_t userId;
    uint64_t challenge;
    uint32_t authType;
    uint32_t authTrustLevel;
};

class UserAuthAdapter {
public:
    static UserAuthAdapter &GetInstance();
    int32_t GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t &authTrustLevel);
    void GetPropAuthInfo(int32_t userId, uint64_t callerUid, const std::string &pkgName,
        const GetPropertyRequest &request, sptr<IUserAuthCallback> &callback);
    void CoAuthSetPropAuthInfo(CallerInfo callerInfo, int32_t resultCode, std::vector<uint8_t> &authToken,
        SetPropertyRequest request);
    void SetPropAuthInfo(CallerInfo callerInfo, int32_t resultCode, std::vector<uint8_t> &authToken,
        SetPropertyRequest request, std::vector<uint64_t> templateIds);
    void GetPropAuthInfoCoAuth(CallerInfo callerInfo, int32_t resultCode, std::vector<uint8_t> &authToken,
        GetPropertyRequest request, sptr<IUserAuthCallback> &callback);
    int32_t GenerateSolution(const AuthSolution &param, std::vector<CoAuth::ScheduleInfo> &scheduleInfos);
    int32_t RequestAuthResult(uint64_t contextId, std::vector<uint8_t> scheduleToken, std::vector<uint8_t> &authToken);
    int32_t CancelContext(uint64_t contextId);
    int32_t Cancel(uint64_t sessionId);
    int32_t GetExecutorProp(uint64_t callerUid, std::string pkgName, uint64_t templateId, GetPropertyRequest request,
        ExecutorProperty &result);
    int32_t SetExecutorProp(uint64_t callerUid, std::string pkgName, SetPropertyRequest request,
        sptr<IUserAuthCallback> &callback);
    int32_t GetVersion();
    int32_t CoAuth(const std::vector<CoAuth::ScheduleInfo> &scheduleInfos, CoAuthInfo coAuthInfo,
        sptr<IUserAuthCallback> &callback);

private:
    UserAuthAdapter() = default;
    ~UserAuthAdapter() = default;
    int32_t GetEachExecutorProp(GetPropertyRequest &request, ExecutorProperty &result, uint32_t &value,
        std::shared_ptr<OHOS::UserIAM::AuthResPool::AuthAttributes> pAuthAttributes);
    int32_t SetProPropAuthInfo(OHOS::UserIAM::AuthResPool::AuthAttributes &authAttributes, CallerInfo callerInfo,
        SetPropertyRequest request, std::vector<uint64_t> templateIds,
        std::shared_ptr<CoAuth::SetPropCallback> &setPropCallback);
    bool CopyScheduleInfo(const HDI::UserAuth::V1_0::ScheduleInfo &in, CoAuth::ScheduleInfo &out);
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // USERAUTH_ADAPTER_H
