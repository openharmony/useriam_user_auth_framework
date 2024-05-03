/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_INTERFACE_H
#define USER_AUTH_INTERFACE_H

#include <cstdint>
#include <optional>

#include "iremote_broker.h"
#include "refbase.h"

#include "attributes.h"
#include "user_auth_callback_interface.h"
#include "user_auth_client_callback.h"
#include "user_auth_interface_ipc_interface_code.h"
#include "widget_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthInterface : public IRemoteBroker {
public:
    virtual int32_t GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel) = 0;

    virtual void GetProperty(int32_t userId, AuthType authType,
        const std::vector<Attributes::AttributeKey> &keys, sptr<GetExecutorPropertyCallbackInterface> &callback) = 0;

    virtual void SetProperty(int32_t userId, AuthType authType, const Attributes &attributes,
        sptr<SetExecutorPropertyCallbackInterface> &callback) = 0;

    virtual uint64_t AuthUser(AuthParamInner &param, std::optional<RemoteAuthParam> &remoteAuthParam,
        sptr<UserAuthCallbackInterface> &callback) = 0;

    virtual uint64_t Auth(int32_t apiVersion, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback) = 0;

    virtual uint64_t AuthWidget(int32_t apiVersion, const AuthParamInner &authParam,
        const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback) = 0;

    virtual uint64_t Identify(const std::vector<uint8_t> &challenge, AuthType authType,
        sptr<UserAuthCallbackInterface> &callback) = 0;

    virtual int32_t CancelAuthOrIdentify(uint64_t contextId) = 0;

    virtual int32_t GetVersion(int32_t &version) = 0;

    virtual int32_t Notice(NoticeType noticeType, const std::string &eventData) = 0;

    virtual int32_t RegisterWidgetCallback(int32_t version, sptr<WidgetCallbackInterface> &callback) = 0;

    virtual int32_t GetEnrolledState(int32_t apiVersion, AuthType authType, EnrolledState &enrolledState) = 0;

    virtual int32_t RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
        const sptr<AuthEventListenerInterface> &listener) = 0;

    virtual int32_t UnRegistUserAuthSuccessEventListener(
        const sptr<AuthEventListenerInterface> &listener) = 0;

    virtual int32_t SetGlobalConfigParam(const GlobalConfigParam &param) = 0;

    virtual int32_t PrepareRemoteAuth(const std::string &networkId, sptr<UserAuthCallbackInterface> &callback) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIam.UserAuth.IUserAuth");
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_INTERFACE_H