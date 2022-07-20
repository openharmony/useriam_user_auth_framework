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

#ifndef CO_AUTH_CLIENT_IMPL_H
#define CO_AUTH_CLIENT_IMPL_H

#include "nocopyable.h"

#include "co_auth_client.h"
#include "co_auth_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthClientImpl final : public CoAuthClient, public NoCopyable {
public:
    void Register(const ExecutorInfo &info, const std::shared_ptr<ExecutorRegisterCallback> &callback) override;
    void Unregister(const ExecutorInfo &info) override;

private:
    friend class CoAuthClient;
    CoAuthClientImpl() = default;
    ~CoAuthClientImpl() override = default;
    sptr<CoAuthInterface> GetProxy();
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_CLIENT_IMPL_H