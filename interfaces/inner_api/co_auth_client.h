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

/**
 * @file co_auth_client.h
 *
 * @brief The definition of coAuth client.
 * @since 3.1
 * @version 3.2
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
    /**
     * @brief Get coAuth client's instance.
     *
     * @return CoAuthClient's instance.
     */
    static CoAuthClient &GetInstance();

    /**
     * @brief Deconstructor.
     */
    virtual ~CoAuthClient() = default;

    /**
     * @brief Executor secure register into coAuth resource pool.
     *
     * @param info Information about executor which need to register into coAuth.
     * @param callback Callback of executor register.
     */
    virtual void Register(const ExecutorInfo &info, const std::shared_ptr<ExecutorRegisterCallback> &callback) = 0;

    /**
     * @brief Executor secure unregister from coAuth resource pool.
     *
     * @param info Information about executor which need to unregister from coAuth.
     */
    virtual void Unregister(uint64_t executorIndex) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_CLIENT_H