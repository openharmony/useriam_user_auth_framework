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

#ifndef USERAUTH_EXCALLBACK_IMPL_H
#define USERAUTH_EXCALLBACK_IMPL_H

#include <mutex>
#include <map>
#include <vector>
#include "iuserauth_callback.h"
#include "userauth_controller.h"
#include "coauth_callback.h"
#include "set_prop_callback.h"
#include "useridm_callback.h"
#include "useridm_info.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuthCallbackImplCoAuth : public std::enable_shared_from_this<UserAuthCallbackImplCoAuth>,
                                   public CoAuth::CoAuthCallback {
public:
    explicit UserAuthCallbackImplCoAuth(const sptr<IUserAuthCallback> &impl, const CoAuthInfo &coAuthInfo,
        bool resultFlag);
    virtual ~UserAuthCallbackImplCoAuth() = default;
    void OnFinish(uint32_t resultCode, std::vector<uint8_t> &scheduleToken) override;
    void OnAcquireInfo(uint32_t acquire) override;
    void OnFinishHandle(uint32_t resultCode, std::vector<uint8_t> scheduleToken);
    void OnAcquireInfoHandle(uint32_t acquire);
    static int32_t SaveCoAuthCallback(uint64_t contextId, std::shared_ptr<CoAuth::CoAuthCallback> coAuthCallback);
    static int32_t DeleteCoAuthCallback(uint64_t contextId);

private:
    void OnFinishHandleExtend(int32_t userId, SetPropertyRequest setPropertyRequest, AuthResult authResult,
        int32_t ret, std::vector<uint8_t> &authToken);
    void DealFinishData();

    uint32_t callbackCount_ = 0;
    uint32_t callbackNowCount_ = 0;
    uint64_t callbackContextId_ = 0;
    std::string pkgName_ = "";
    int32_t userId_ = 0;
    uint64_t callerUid_ = 0;
    bool isResultDoneFlag_ = false;
    sptr<IUserAuthCallback> callback_ { nullptr };
    AuthType authType_;
    std::mutex mutex_;
    static std::mutex coAuthCallbackMutex_;
    static std::map<uint64_t, std::shared_ptr<CoAuth::CoAuthCallback>> saveCoAuthCallback_;
};

class UserAuthCallbackImplSetProp : public CoAuth::SetPropCallback {
public:
    explicit UserAuthCallbackImplSetProp(const sptr<IUserAuthCallback>& impl);
    virtual ~UserAuthCallbackImplSetProp() = default;

    void OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)  override;

private:
    sptr<IUserAuthCallback> callback_ { nullptr };
};

class UserAuthCallbackImplSetPropFreeze : public CoAuth::SetPropCallback {
public:
    UserAuthCallbackImplSetPropFreeze(std::vector<uint64_t> templateIds, std::vector<uint8_t> &authToken,
        FreezeInfo freezeInfo);
    virtual ~UserAuthCallbackImplSetPropFreeze() = default;

    void OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)  override;

private:
    std::vector<uint64_t> templateIds_;
    int32_t resultCode_;
    std::vector<uint8_t> authToken_;
    AuthType authType_;
    std::string pkgName_;
    uint64_t callerUid_;
};

class UserAuthCallbackImplIdmGetProp : public UserIDM::GetInfoCallback {
public:
    explicit UserAuthCallbackImplIdmGetProp(const sptr<IUserAuthCallback> &impl, GetPropertyRequest request,
        uint64_t callerUid, std::string pkgName);
    virtual ~UserAuthCallbackImplIdmGetProp() = default;

    void OnGetInfo(std::vector<UserIDM::CredentialInfo>& info) override;

private:
    sptr<IUserAuthCallback> callback_ { nullptr };
    GetPropertyRequest request_;
    std::string pkgName_;
    uint64_t callerUid_;
};

class UserAuthCallbackImplIdmCoAuthGetPropFreeze : public UserIDM::GetInfoCallback {
public:
    explicit UserAuthCallbackImplIdmCoAuthGetPropFreeze(uint64_t callerUid, std::string pkgName, int32_t resultCode,
        std::vector<uint8_t> &authToken, SetPropertyRequest request);
    virtual ~UserAuthCallbackImplIdmCoAuthGetPropFreeze() = default;

    void OnGetInfo(std::vector<UserIDM::CredentialInfo>& info) override;

private:
    std::vector<uint8_t> authToken_;
    int32_t resultCode_;
    SetPropertyRequest request_;
    std::string pkgName_;
    uint64_t callerUid_;
};

class UserAuthCallbackImplIdmGetPropCoAuth : public UserIDM::GetInfoCallback {
public:
    explicit UserAuthCallbackImplIdmGetPropCoAuth(const sptr<IUserAuthCallback> &impl, uint64_t callerUid,
        std::string pkgName, int32_t resultCode, std::vector<uint8_t> &authToken, GetPropertyRequest request);
    virtual ~UserAuthCallbackImplIdmGetPropCoAuth() = default;

    void OnGetInfo(std::vector<UserIDM::CredentialInfo>& info) override;

private:
    sptr<IUserAuthCallback> callback_ { nullptr };
    std::vector<uint8_t> authToken_;
    int32_t resultCode_;
    GetPropertyRequest request_;
    std::string pkgName_;
    uint64_t callerUid_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USERAUTH_EXCALLBACK_IMPL_H
