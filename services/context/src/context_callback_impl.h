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

#ifndef CONTEXT_CALLBACK_IMPL_H
#define CONTEXT_CALLBACK_IMPL_H

#include "context.h"

#include "user_auth_callback.h"
#include "user_idm_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ContextCallbackImpl : public ContextCallback, public NoCopyable {
public:
    explicit ContextCallbackImpl(sptr<IdmCallback> idmCallback);
    explicit ContextCallbackImpl(sptr<UserAuthCallback> userAuthCallback);
    ~ContextCallbackImpl() override = default;
    void onAcquireInfo(ExecutorRole src, int32_t moduleType, const std::vector<uint8_t> &acquireMsg) const override;
    void OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &finalResult) const override;

private:
    sptr<IdmCallback> idmCallback_;
    sptr<UserAuthCallback> userAuthCallback_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CONTEXT_CALLBACK_IMPL_H