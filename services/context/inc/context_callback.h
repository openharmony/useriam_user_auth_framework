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

#ifndef IAM_CONTEXT_CALLBACK_H
#define IAM_CONTEXT_CALLBACK_H

#include <cstdint>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <singleton.h>
#include <vector>

#include "context.h"
#include "iam_defines.h"
#include "user_auth_callback_interface.h"
#include "user_idm_callback_interface.h"
#include "iam_callback_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextCallbackNotifyListener : public Singleton<ContextCallbackNotifyListener> {
public:
    struct MetaData {
        OperationType operationType;
        int32_t operationResult;
        std::optional<int32_t> userId;
        std::optional<int32_t> remainTime;
        std::optional<int32_t> freezingTime;
        std::optional<int32_t> sdkVersion;
        std::optional<uint64_t> callingUid;
        std::optional<AuthTrustLevel> atl;
        std::optional<AuthType> authType;
        std::chrono::time_point<std::chrono::steady_clock> startTime;
        std::chrono::time_point<std::chrono::steady_clock> endTime;
    };
    using Notify = std::function<void(const MetaData &metaData)>;
    void AddNotifier(const Notify &notify);
    void Process(const MetaData &metaData);

private:
    std::vector<Notify> notifierList_;
};

class ContextCallback {
public:
    static std::shared_ptr<ContextCallback> NewInstance(sptr<IamCallbackInterface> iamCallback,
        OperationType operationType);
    virtual ~ContextCallback() = default;
    virtual void OnResult(int32_t resultCode, const Attributes &finalResult) = 0;
    virtual void OnAcquireInfo(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg) const = 0;
    virtual void SetTraceUserId(int32_t userId) = 0;
    virtual void SetTraceRemainTime(int32_t remainTime) = 0;
    virtual void SetTraceFreezingTime(int32_t freezingTime) = 0;
    virtual void SetTraceSdkVersion(int32_t version) = 0;
    virtual void SetTraceCallingUid(uint64_t callingUid) = 0;
    virtual void SetTraceAuthType(AuthType authType) = 0;
    virtual void SetTraceAuthTrustLevel(AuthTrustLevel atl) = 0;
    virtual void SetCleaner(Context::ContextStopCallback callback) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_CALLBACK_H