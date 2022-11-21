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

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::shared_ptr<Context> ContextFactory::CreateSimpleAuthContext(const AuthContextPara &para,
    const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto auth = Common::MakeShared<AuthenticationImpl>(newContextId, para.userId, para.authType, para.atl);
    IF_FALSE_LOGE_AND_RETURN_VAL(auth != nullptr, nullptr);
    auth->SetChallenge(para.challenge);
    auth->SetAccessTokenId(para.tokenId);
    return Common::MakeShared<SimpleAuthContext>(newContextId, auth, callback);
}

std::shared_ptr<Context> ContextFactory::CreateIdentifyContext(const IdentifyContextPara &para,
    const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto identify = Common::MakeShared<IdentificationImpl>(newContextId, para.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(identify != nullptr, nullptr);
    identify->SetChallenge(para.challenge);
    identify->SetAccessTokenId(para.tokenId);
    return Common::MakeShared<IdentifyContext>(newContextId, identify, callback);
}

std::shared_ptr<Context> ContextFactory::CreateEnrollContext(const EnrollContextPara &para,
    const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto enroll = Common::MakeShared<EnrollmentImpl>(para.userId, para.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(enroll != nullptr, nullptr);
    enroll->SetAuthToken(para.token);
    enroll->SetAccessTokenId(para.tokenId);
    enroll->SetPinSubType(para.pinType);
    return Common::MakeShared<EnrollContext>(newContextId, enroll, callback);
}

std::shared_ptr<Context> ContextFactory::CreateWidgetAuthContext(std::shared_ptr<ContextCallback> callback)
{
    return nullptr;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
