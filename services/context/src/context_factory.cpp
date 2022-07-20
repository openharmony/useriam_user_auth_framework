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
#include "context_factory.h"

#include "authentication_impl.h"
#include "context_callback_impl.h"
#include "context_pool.h"
#include "enroll_context.h"
#include "enrollment_impl.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "identification_impl.h"
#include "identify_context.h"
#include "simple_auth_context.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

using namespace OHOS::UserIAM::Common;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::shared_ptr<Context> ContextFactory::CreateSimpleAuthContext(int32_t userId, const std::vector<uint8_t> &challenge,
    AuthType authType, AuthTrustLevel authTrustLevel, uint32_t tokenId,
    const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto auth = MakeShared<AuthenticationImpl>(newContextId, userId, authType, authTrustLevel);
    IF_FALSE_LOGE_AND_RETURN_VAL(auth != nullptr, nullptr);
    auth->SetChallenge(challenge);
    auth->SetAccessTokenId(tokenId);
    return MakeShared<SimpleAuthContext>(newContextId, auth, callback);
}

std::shared_ptr<Context> ContextFactory::CreateIdentifyContext(const std::vector<uint8_t> &challenge, AuthType authType,
    uint32_t tokenId, const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto identify = MakeShared<IdentificationImpl>(newContextId, authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(identify != nullptr, nullptr);
    identify->SetChallenge(challenge);
    identify->SetAccessTokenId(tokenId);
    return MakeShared<IdentifyContext>(newContextId, identify, callback);
}

std::shared_ptr<Context> ContextFactory::CreateEnrollContext(int32_t userId, AuthType authType, PinSubType pinSubType,
    const std::vector<uint8_t> &token, uint32_t tokenId, const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto enroll = MakeShared<EnrollmentImpl>(userId, authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(enroll != nullptr, nullptr);
    enroll->SetAuthToken(token);
    enroll->SetAccessTokenId(tokenId);
    enroll->SetPinSubType(pinSubType);
    return MakeShared<EnrollContext>(newContextId, enroll, callback);
}

std::shared_ptr<Context> ContextFactory::CreateWidgetAuthContext(std::shared_ptr<ContextCallback> callback)
{
    return nullptr;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
