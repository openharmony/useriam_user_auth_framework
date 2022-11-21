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
    struct AuthContextPara {
        int32_t userId {0};
        AuthType authType {ALL};
        AuthTrustLevel atl {ATL1};
        uint32_t tokenId {0};
        std::vector<uint8_t> challenge;
    };

    struct IdentifyContextPara {
        AuthType authType {ALL};
        uint32_t tokenId {0};
        std::vector<uint8_t> challenge;
    };

    struct EnrollContextPara {
        int32_t userId {0};
        AuthType authType {ALL};
        PinSubType pinType {PIN_SIX};
        uint32_t tokenId {0};
        std::vector<uint8_t> token;
    };
    static std::shared_ptr<Context> CreateSimpleAuthContext(const AuthContextPara &para,
        const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateIdentifyContext(const IdentifyContextPara &para,
        const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateEnrollContext(const EnrollContextPara &para,
        const std::shared_ptr<ContextCallback> &callback);
    static std::shared_ptr<Context> CreateWidgetAuthContext(std::shared_ptr<ContextCallback> callback);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_CONTEXT_FACTORY_H