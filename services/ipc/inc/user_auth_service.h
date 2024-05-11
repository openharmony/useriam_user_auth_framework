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

#ifndef USER_AUTH_SERVICE_H
#define USER_AUTH_SERVICE_H

#include "user_auth_stub.h"

#include <string>
#include <system_ability.h>
#include <system_ability_definition.h>

#include "context_callback.h"
#include "context_factory.h"
#include "context_pool.h"
#include "resource_node_pool.h"
#include "user_idm_database.h"
#include "attributes.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthService : public SystemAbility, public UserAuthStub, public NoCopyable {
public:
    DECLARE_SYSTEM_ABILITY(UserAuthService);
    static std::shared_ptr<UserAuthService> GetInstance();

    UserAuthService();
    ~UserAuthService() override = default;
    int32_t GetAvailableStatus(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel) override;
    void GetProperty(int32_t userId, AuthType authType,
        const std::vector<Attributes::AttributeKey> &keys,
        sptr<GetExecutorPropertyCallbackInterface> &callback) override;
    void SetProperty(int32_t userId, AuthType authType, const Attributes &attributes,
        sptr<SetExecutorPropertyCallbackInterface> &callback) override;
    uint64_t AuthUser(AuthParamInner &param, std::optional<RemoteAuthParam> &remoteAuthParam,
        sptr<UserAuthCallbackInterface> &callback) override;
    uint64_t Auth(int32_t apiVersion, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback) override;
    uint64_t AuthWidget(int32_t apiVersion, const AuthParamInner &authParam,
        const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback) override;
    uint64_t Identify(const std::vector<uint8_t> &challenge, AuthType authType,
        sptr<UserAuthCallbackInterface> &callback) override;
    int32_t CancelAuthOrIdentify(uint64_t contextId) override;
    int32_t GetVersion(int32_t &version) override;
    int32_t Notice(NoticeType noticeType, const std::string &eventData) override;
    int32_t RegisterWidgetCallback(int32_t version, sptr<WidgetCallbackInterface> &callback) override;
    int32_t GetEnrolledState(int32_t apiVersion, AuthType authType, EnrolledState &enrolledState) override;
    int32_t RegistUserAuthSuccessEventListener(const std::vector<AuthType> &authType,
        const sptr<AuthEventListenerInterface> &listener) override;
    int32_t UnRegistUserAuthSuccessEventListener(const sptr<AuthEventListenerInterface> &listener) override;
    int32_t SetGlobalConfigParam(const GlobalConfigParam &param) override;
    int32_t PrepareRemoteAuth(const std::string &networkId, sptr<UserAuthCallbackInterface> &callback) override;
    int32_t ProcStartRemoteAuthRequest(std::string connectionName, const std::shared_ptr<Attributes> &request,
        std::shared_ptr<Attributes> &reply);

protected:
    void OnStart() override;
    void OnStop() override;

private:
    std::shared_ptr<ContextCallback> GetAuthContextCallback(int32_t apiVersion,
        const std::vector<uint8_t> &challenge, AuthType authType, AuthTrustLevel authTrustLevel,
        sptr<UserAuthCallbackInterface> &callback);
    std::shared_ptr<ContextCallback> GetAuthContextCallback(int32_t apiVersion,
        const AuthParamInner &authParam, const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback);
    bool CheckAuthTrustLevel(AuthTrustLevel authTrustLevel);
    bool CheckSingeFaceOrFinger(const std::vector<AuthType> &authType);
    int32_t CheckAuthWidgetType(const std::vector<AuthType> &authType);
    int32_t CheckAuthPermissionAndParam(int32_t userId, const AuthParamInner &authParam,
        const WidgetParam &widgetParam);
    uint64_t StartWidgetContext(const std::shared_ptr<ContextCallback> &contextCallback,
        const AuthParamInner &authParam, const WidgetParam &widgetParam, std::vector<AuthType> &validType,
        ContextFactory::AuthWidgetContextPara &para);
    uint64_t StartAuthContext(int32_t apiVersion, Authentication::AuthenticationPara para,
        const std::shared_ptr<ContextCallback> &contextCallback);
    uint64_t AuthRemoteUser(AuthParamInner &authParam, Authentication::AuthenticationPara &para,
        RemoteAuthParam &remoteAuthParam, const std::shared_ptr<ContextCallback> &contextCallback,
        ResultCode &failReason);
    uint64_t StartRemoteAuthContext(Authentication::AuthenticationPara para,
        RemoteAuthContextParam remoteAuthContextParam,
        const std::shared_ptr<ContextCallback> &contextCallback, int &lastError);
    uint64_t StartRemoteAuthInvokerContext(AuthParamInner authParam,
        RemoteAuthInvokerContextParam &param, const std::shared_ptr<ContextCallback> &contextCallback);
    bool Insert2ContextPool(const std::shared_ptr<Context> &context);
    bool CheckCallerIsSystemApp();
    int32_t CheckAuthPermissionAndParam(int32_t authType, const int32_t &callerType, const std::string &callerName,
        AuthTrustLevel authTrustLevel);
    bool CheckAuthPermissionAndParam(AuthType authType, AuthTrustLevel authTrustLevel,
        const std::shared_ptr<ContextCallback> &contextCallback, Attributes &extraInfo);
    bool CheckAuthTypeIsValid(std::vector<AuthType> authType);
    int32_t CheckValidSolution(int32_t userId, const AuthParamInner &authParam, const WidgetParam &widgetParam,
        std::vector<AuthType> &validType);
    int32_t GetCallerNameAndUserId(ContextFactory::AuthWidgetContextPara &para,
        std::shared_ptr<ContextCallback> &contextCallback);
    void FillGetPropertyKeys(AuthType authType, const std::vector<Attributes::AttributeKey> keys,
        std::vector<uint32_t> &uint32Keys);
    void FillGetPropertyValue(AuthType authType, const std::vector<Attributes::AttributeKey> keys, Attributes &value);
    bool CompleteRemoteAuthParam(RemoteAuthParam &remoteAuthParam, const std::string &localNetworkId);
    int32_t PrepareRemoteAuthInner(const std::string &networkId);

    static std::mutex mutex_;
    static std::shared_ptr<UserAuthService> instance_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_SERVICE_H