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

#ifndef IAM_CONTEXT_FACTORY_H
#define IAM_CONTEXT_FACTORY_H

#include <cstdint>
#include <memory>

#include "singleton.h"

#include "context.h"
#include "context_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextFactory : public DelayedSingleton<ContextFactory> {
public:
    static std::shared_ptr<Context> CreateSimpleAuthContext(int32_t userId, const std::vector<uint8_t> &challenge,
        AuthType authType, AuthTrustLevel authTrustLevel, uint64_t callingUid,
        const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateIdentifyContext(const std::vector<uint8_t> &challenge, AuthType authType,
        uint64_t callingUid, const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateEnrollContext(int32_t userId, AuthType authType, PinSubType pinSubType,
        const std::vector<uint8_t> &token, uint64_t callingUid, const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateWidgetAuthContext(std::shared_ptr<ContextCallback> callback);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_FACTORY_H