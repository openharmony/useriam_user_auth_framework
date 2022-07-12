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

#ifndef CO_AUTH_CLIENT_H
#define CO_AUTH_CLIENT_H

#include "co_auth_client_callback.h"
#include "co_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthClient {
public:
    static CoAuthClient &GetInstance();
    virtual ~CoAuthClient() = default;

    virtual void Register(const ExecutorInfo &info, const std::shared_ptr<ExecutorRegisterCallback> &callback) = 0;
    virtual void Unregister(const ExecutorInfo &info) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_CLIENT_H