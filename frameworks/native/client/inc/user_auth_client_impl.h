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

#ifndef USER_AUTH_CLIENT_IMPL_H
#define USER_AUTH_CLIENT_IMPL_H

#include <mutex>
#include <optional>

#include "nocopyable.h"

#include "user_auth_client.h"
#include "user_auth_interface.h"
#include "iuser_auth_widget_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthClientImpl final : public UserAuthClient, NoCopyable {
public:
    static UserAuthClientImpl& Instance();
    int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel);
    int32_t GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel);
    void GetProperty(int32_t userId, const GetPropertyRequest &request,
        const std::shared_ptr<GetPropCallback> &callback) override;
    void SetProperty(int32_t userId, const SetPropertyRequest &request,
        const std::shared_ptr<SetPropCallback> &callback) override;
    uint64_t BeginAuthentication(const AuthParam &authParam,
        const std::shared_ptr<AuthenticationCallback> &callback) override;
    uint64_t BeginNorthAuthentication(int32_t apiVersion, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel atl, const std::shared_ptr<AuthenticationCallback> &callback);
    int32_t CancelAuthentication(uint64_t contextId) override;
    uint64_t BeginIdentification(const std::vector<uint8_t> &challenge, AuthType authType,
        const std::shared_ptr<IdentificationCallback> &callback) override;
    int32_t CancelIdentification(uint64_t contextId) override;
    int32_t GetVersion(int32_t &version);
    uint64_t BeginWidgetAuth(int32_t apiVersion, const AuthParamInner &authParam,
        const WidgetParam &widgetParam, const std::shared_ptr<AuthenticationCallback> &callback);
    int32_t SetWidgetCallback(int32_t version, const std::shared_ptr<IUserAuthWidgetCallback> &callback);
    int32_t Notice(NoticeType noticeType, const std::string &eventData);
    int32_t GetEnrolledState(int32_t apiVersion, AuthType authType, EnrolledState &enrolledState);
    int32_t RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
        const sptr<AuthEventListenerInterface> &listener) override;
    int32_t UnRegistUserAuthSuccessEventListener(
        const sptr<AuthEventListenerInterface> &listener) override;
    int32_t SetGlobalConfigParam(const GlobalConfigParam &param) override;
    int32_t PrepareRemoteAuth(const std::string &networkId,
        const std::shared_ptr<PrepareRemoteAuthCallback> &callback) override;

private:
    ResultCode SetPropertyInner(int32_t userId, const SetPropertyRequest &request,
        const std::shared_ptr<SetPropCallback> &callback);

    friend class UserAuthClient;
    UserAuthClientImpl() = default;
    ~UserAuthClientImpl() override = default;
    class UserAuthImplDeathRecipient : public IRemoteObject::DeathRecipient, public NoCopyable {
    public:
        UserAuthImplDeathRecipient() = default;
        ~UserAuthImplDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    void ResetProxy(const wptr<IRemoteObject> &remote);
    sptr<UserAuthInterface> GetProxy();
    sptr<UserAuthInterface> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
    constexpr static int32_t MINIMUM_VERSION {0};
    constexpr static uint64_t INVALID_SESSION_ID {0};
    std::mutex mutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_CLIENT_IMPL_H