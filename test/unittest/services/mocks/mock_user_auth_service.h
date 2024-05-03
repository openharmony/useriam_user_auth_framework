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
#ifndef IAM_MOCK_USER_AUTH_SERVICE_H
#define IAM_MOCK_USER_AUTH_SERVICE_H

#include <gmock/gmock.h>

#include "user_auth_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserAuthService final : public UserAuthStub {
public:
    MOCK_METHOD3(GetEnrolledState, int32_t(int32_t apiVersion, AuthType authType, EnrolledState &enrolledState));

    MOCK_METHOD3(GetAvailableStatus, int32_t(int32_t apiVersion, AuthType authType, AuthTrustLevel authTrustLevel));

    MOCK_METHOD4(GetProperty,
        void(int32_t userId, AuthType authType, const std::vector<Attributes::AttributeKey> &keys,
            sptr<GetExecutorPropertyCallbackInterface> &callback));

    MOCK_METHOD4(SetProperty, void(int32_t userId, AuthType authType, const Attributes &attributes,
                                  sptr<SetExecutorPropertyCallbackInterface> &callback));

    MOCK_METHOD3(AuthUser, uint64_t(AuthParamInner &param, std::optional<RemoteAuthParam> &remoteAuthParam,
        sptr<UserAuthCallbackInterface> &callback));
    
    MOCK_METHOD5(Auth,
        uint64_t(int32_t apiVersion, const std::vector<uint8_t> &challenge, AuthType authType,
            AuthTrustLevel authTrustLevel, sptr<UserAuthCallbackInterface> &callback));

    MOCK_METHOD4(AuthWidget, uint64_t(int32_t apiVersion, const AuthParamInner &authParam,
        const WidgetParam &widgetParam, sptr<UserAuthCallbackInterface> &callback));

    MOCK_METHOD3(Identify,
        uint64_t(const std::vector<uint8_t> &challenge, AuthType authType, sptr<UserAuthCallbackInterface> &callback));

    MOCK_METHOD1(CancelAuthOrIdentify, int32_t(uint64_t contextId));
    MOCK_METHOD1(GetVersion, int32_t(int32_t &version));
    MOCK_METHOD2(Notice, int32_t(NoticeType noticeType, const std::string &eventData));
    MOCK_METHOD2(RegisterWidgetCallback, int32_t(int32_t version, sptr<WidgetCallbackInterface> &callback));
    MOCK_METHOD2(RegistUserAuthSuccessEventListener, int32_t(const std::vector<AuthType> &authType,
        const sptr<AuthEventListenerInterface> &callback));
    MOCK_METHOD1(UnRegistUserAuthSuccessEventListener, int32_t(const sptr<AuthEventListenerInterface> &callback));
    MOCK_METHOD1(SetGlobalConfigParam, int32_t(const GlobalConfigParam &param));
    MOCK_METHOD2(PrepareRemoteAuth, int32_t(const std::string &networkId, sptr<UserAuthCallbackInterface> &callback));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_USER_AUTH_SERVICE_H