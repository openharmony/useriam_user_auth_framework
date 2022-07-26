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

#ifndef IAUTH_EXECUTOR_HDI_H
#define IAUTH_EXECUTOR_HDI_H

#include <cstdint>
#include <vector>

#include "co_auth_client.h"
#include "framework_types.h"
#include "iam_common_defines.h"
#include "iexecute_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IAuthExecutorHdi {
public:
    IAuthExecutorHdi() = default;
    virtual ~IAuthExecutorHdi() = default;

    virtual ResultCode GetExecutorInfo(ExecutorInfo &info) = 0;
    virtual ResultCode GetTemplateInfo(uint64_t templateId, UserAuth::TemplateInfo &info) = 0;
    virtual ResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) = 0;
    virtual ResultCode Enroll(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) = 0;
    virtual ResultCode Authenticate(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &extraInfo, const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) = 0;
    virtual ResultCode Identify(uint64_t scheduleId, uint32_t tokenId, const std::vector<uint8_t> &extraInfo,

        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) = 0;
    virtual ResultCode Delete(const std::vector<uint64_t> &templateIdList) = 0;
    virtual ResultCode Cancel(uint64_t scheduleId) = 0;
    virtual ResultCode SendCommand(PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAUTH_EXECUTOR_HDI_H