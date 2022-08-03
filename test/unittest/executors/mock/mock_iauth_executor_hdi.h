/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"));
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

#ifndef MOCK_IAUTH_EXECUTOR_HDI_H
#define MOCK_IAUTH_EXECUTOR_HDI_H

#include "gmock/gmock.h"

#include "mock_iauth_executor_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::UserIam;
using namespace OHOS::UserIam::UserAuth;

class MockIAuthExecutorHdi : public IAuthExecutorHdi {
public:
    virtual ~MockIAuthExecutorHdi() = default;

    MOCK_METHOD1(GetExecutorInfo, ResultCode(ExecutorInfo &info));
    MOCK_METHOD2(GetTemplateInfo, ResultCode(uint64_t templateId, UserAuth::TemplateInfo &info));
    MOCK_METHOD3(
        OnRegisterFinish, ResultCode(const std::vector<uint64_t> &templateIdList,
                              const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo));
    MOCK_METHOD4(Enroll, ResultCode(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
                             const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj));
    MOCK_METHOD5(Authenticate,
        ResultCode(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint64_t> &templateIdList,
            const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj));
    MOCK_METHOD4(Identify, ResultCode(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
                               const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj));
    MOCK_METHOD1(Delete, ResultCode(const std::vector<uint64_t> &templateIdList));
    MOCK_METHOD1(Cancel, ResultCode(uint64_t scheduleId));
    MOCK_METHOD3(SendCommand, ResultCode(PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
                                  const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_IAUTH_EXECUTOR_HDI_H