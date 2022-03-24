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

#ifndef IUSERAUTH_H
#define IUSERAUTH_H

#include <iremote_broker.h>
#include "iuserauth_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class IUserAuth : public IRemoteBroker {
public:
    enum {
        USER_AUTH_GET_AVAILABLE_STATUS = 0,
        USER_AUTH_GET_PROPERTY,
        USER_AUTH_SET_PROPERTY,
        USER_AUTH_AUTH,
        USER_AUTH_AUTH_USER,
        USER_AUTH_CANCEL_AUTH,
        USER_AUTH_GET_VERSION,
        USER_AUTH_ON_RESULT,
        USER_AUTH_GET_EX_PROP,
        USER_AUTH_SET_EX_PROP,
        USER_AUTH_ACQUIRE_INFO
    };

    virtual int32_t GetAvailableStatus(const AuthType authType, AuthTrustLevel authTrustLevel) = 0;
    virtual void GetProperty(const GetPropertyRequest request, sptr<IUserAuthCallback> &callback) = 0;
    virtual void SetProperty(const SetPropertyRequest request, sptr<IUserAuthCallback> &callback) = 0;
    virtual uint64_t Auth(const uint64_t challenge, const AuthType authType, const AuthTrustLevel authTrustLevel,
        sptr<IUserAuthCallback> &callback) = 0;
    virtual uint64_t AuthUser(const int32_t userId, const uint64_t challenge, const AuthType authType,
        const AuthTrustLevel authTrustLevel, sptr<IUserAuthCallback> &callback) = 0;
    virtual int32_t CancelAuth(const uint64_t contextId) = 0;
    virtual int32_t GetVersion() = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIAM.UserAuth.IUserAuth");
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // IUSERAUTH_H