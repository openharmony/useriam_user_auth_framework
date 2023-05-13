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
#include "user_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockIUserAuthInterface final : public IUserAuthInterface {
public:
    class Holder;
    MOCK_METHOD0(Init, int32_t());

    MOCK_METHOD4(AddExecutor, int32_t(const HdiExecutorRegisterInfo &info, uint64_t &index,
                                  std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds));
    MOCK_METHOD1(DeleteExecutor, int32_t(uint64_t index));
    MOCK_METHOD2(OpenSession, int32_t(int32_t userId, std::vector<uint8_t> &challenge));
    MOCK_METHOD1(CloseSession, int32_t(int32_t userId));
    MOCK_METHOD4(BeginEnrollment,
        int32_t(int32_t userId, const std::vector<uint8_t> &authToken, const HdiEnrollParam &param,
            HdiScheduleInfoV1_0 &info));
    MOCK_METHOD3(UpdateEnrollmentResult, int32_t(int32_t userId, const std::vector<uint8_t> &scheduleResult,
                                             HdiEnrollResultInfo &info));
    MOCK_METHOD1(CancelEnrollment, int32_t(int32_t userId));
    MOCK_METHOD4(DeleteCredential,
        int32_t(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, HdiCredentialInfo &info));
    MOCK_METHOD3(GetCredential, int32_t(int32_t userId, HdiAuthType authType, std::vector<HdiCredentialInfo> &infos));

    MOCK_METHOD4(GetUserInfo,
        int32_t(int32_t userId, uint64_t &secureUid, HdiPinSubType &pinSubType, std::vector<HdiEnrolledInfo> &infos));
    MOCK_METHOD3(DeleteUser,
        int32_t(int32_t userId, const std::vector<uint8_t> &authToken, std::vector<HdiCredentialInfo> &deletedInfos));
    MOCK_METHOD2(EnforceDeleteUser, int32_t(int32_t userId, std::vector<HdiCredentialInfo> &deletedInfos));
    MOCK_METHOD3(BeginAuthentication,
        int32_t(uint64_t contextId, const HdiAuthSolution &param, std::vector<HdiScheduleInfoV1_0> &scheduleInfos));
    MOCK_METHOD3(UpdateAuthenticationResult,
        int32_t(uint64_t contextId, const std::vector<uint8_t> &scheduleResult, HdiAuthResultInfo &info));
    MOCK_METHOD1(CancelAuthentication, int32_t(uint64_t contextId));
    MOCK_METHOD5(BeginIdentification,
        int32_t(uint64_t contextId, HdiAuthType authType, const std::vector<uint8_t> &challenge, uint32_t executorId,
            HdiScheduleInfoV1_0 &scheduleInfo));
    MOCK_METHOD3(UpdateIdentificationResult,
        int32_t(uint64_t contextId, const std::vector<uint8_t> &scheduleResult, HdiIdentifyResultInfo &info));
    MOCK_METHOD1(CancelIdentification, int32_t(uint64_t contextId));
    MOCK_METHOD3(GetAuthTrustLevel, int32_t(int32_t userId, HdiAuthType authType, uint32_t &authTrustLevel));
    MOCK_METHOD4(GetValidSolution, int32_t(int32_t userId, const std::vector<HdiAuthType> &authTypes,
                                       uint32_t authTrustLevel, std::vector<HdiAuthType> &validTypes));
    MOCK_METHOD4(BeginEnrollmentV1_1,
        int32_t(int32_t userId, const std::vector<uint8_t> &authToken, const HdiEnrollParam &param,
            HdiScheduleInfo &info));
    MOCK_METHOD3(BeginAuthenticationV1_1,
        int32_t(uint64_t contextId, const HdiAuthSolution &param, std::vector<HdiScheduleInfo> &scheduleInfos));
    MOCK_METHOD5(BeginIdentificationV1_1,
        int32_t(uint64_t contextId, HdiAuthType authType, const std::vector<uint8_t> &challenge, uint32_t executorId,
            HdiScheduleInfo &scheduleInfo));
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