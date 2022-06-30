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
#ifndef IAM_MOCK_IUSER_AUTH_INTERFACE_H
#define IAM_MOCK_IUSER_AUTH_INTERFACE_H

#include <memory>
#include <mutex>

#include <gmock/gmock.h>

#include "singleton.h"

#include "hdi_wrapper.h"
#include "v1_0/iuser_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIUserAuthInterface final : public HDI::UserAuth::V1_0::IUserAuthInterface {
public:
    using ExecutorRegisterInfo = OHOS::HDI::UserAuth::V1_0::ExecutorRegisterInfo;
    using EnrollParam = OHOS::HDI::UserAuth::V1_0::EnrollParam;
    using ScheduleInfo = OHOS::HDI::UserAuth::V1_0::ScheduleInfo;
    using CredentialInfo = OHOS::HDI::UserAuth::V1_0::CredentialInfo;
    using EnrolledInfo = OHOS::HDI::UserAuth::V1_0::EnrolledInfo;
    using AuthType = OHOS::HDI::UserAuth::V1_0::AuthType;
    using PinSubType = OHOS::HDI::UserAuth::V1_0::PinSubType;
    using AuthSolution = OHOS::HDI::UserAuth::V1_0::AuthSolution;
    using AuthResultInfo = OHOS::HDI::UserAuth::V1_0::AuthResultInfo;
    using IdentifyResultInfo = OHOS::HDI::UserAuth::V1_0::IdentifyResultInfo;
    using EnrollResultInfo = OHOS::HDI::UserAuth::V1_0::EnrollResultInfo;

    class Holder;
    MOCK_METHOD0(Init, int32_t());

    MOCK_METHOD4(AddExecutor, int32_t(const ExecutorRegisterInfo &info, uint64_t &index,
                                  std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds));
    MOCK_METHOD1(DeleteExecutor, int32_t(uint64_t index));
    MOCK_METHOD2(OpenSession, int32_t(int32_t userId, std::vector<uint8_t> &challenge));
    MOCK_METHOD1(CloseSession, int32_t(int32_t userId));
    MOCK_METHOD4(BeginEnrollment,
        int32_t(int32_t userId, const std::vector<uint8_t> &authToken, const EnrollParam &param, ScheduleInfo &info));
    MOCK_METHOD3(UpdateEnrollmentResult, int32_t(int32_t userId, const std::vector<uint8_t> &scheduleResult,
                                             EnrollResultInfo &info));
    MOCK_METHOD1(CancelEnrollment, int32_t(int32_t userId));
    MOCK_METHOD4(DeleteCredential,
        int32_t(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, CredentialInfo &info));
    MOCK_METHOD3(GetCredential, int32_t(int32_t userId, AuthType authType, std::vector<CredentialInfo> &infos));

    MOCK_METHOD4(GetUserInfo,
        int32_t(int32_t userId, uint64_t &secureUid, PinSubType &pinSubType, std::vector<EnrolledInfo> &infos));
    MOCK_METHOD3(DeleteUser,
        int32_t(int32_t userId, const std::vector<uint8_t> &authToken, std::vector<CredentialInfo> &deletedInfos));
    MOCK_METHOD2(EnforceDeleteUser, int32_t(int32_t userId, std::vector<CredentialInfo> &deletedInfos));
    MOCK_METHOD3(BeginAuthentication,
        int32_t(uint64_t contextId, const AuthSolution &param, std::vector<ScheduleInfo> &scheduleInfos));
    MOCK_METHOD3(UpdateAuthenticationResult,
        int32_t(uint64_t contextId, const std::vector<uint8_t> &scheduleResult, AuthResultInfo &info));
    MOCK_METHOD1(CancelAuthentication, int32_t(uint64_t contextId));
    MOCK_METHOD5(BeginIdentification,
        int32_t(uint64_t contextId, AuthType authType, const std::vector<uint8_t> &challenge, uint32_t executorId,
            ScheduleInfo &scheduleInfo));
    MOCK_METHOD3(UpdateIdentificationResult,
        int32_t(uint64_t contextId, const std::vector<uint8_t> &scheduleResult, IdentifyResultInfo &info));
    MOCK_METHOD1(CancelIdentification, int32_t(uint64_t contextId));
    MOCK_METHOD3(GetAuthTrustLevel, int32_t(int32_t userId, AuthType authType, uint32_t &authTrustLevel));
    MOCK_METHOD4(GetValidSolution, int32_t(int32_t userId, const std::vector<AuthType> &authTypes,
                                       uint32_t authTrustLevel, std::vector<AuthType> &validTypes));
};

class MockIUserAuthInterface::Holder : public Singleton<MockIUserAuthInterface::Holder> {
public:
    void Reset();
    std::shared_ptr<MockIUserAuthInterface> Get();

private:
    std::mutex mutex_;
    std::shared_ptr<MockIUserAuthInterface> mock_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_IUSER_AUTH_INTERFACE_H