/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef CO_AUTH_SERVICE_H
#define CO_AUTH_SERVICE_H

#include "co_auth_stub.h"

#include <system_ability.h>
#include <system_ability_definition.h>
#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthService : public SystemAbility, public CoAuthStub {
public:
    static constexpr uint64_t DEFER_TIME = 2000;
    DECLARE_SYSTEM_ABILITY(CoAuthService);
    static std::shared_ptr<CoAuthService> GetInstance();

    CoAuthService();
    ~CoAuthService() override = default;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    uint64_t ExecutorRegister(const ExecutorRegisterInfo &info, sptr<ExecutorCallbackInterface> &callback) override;
    void ExecutorUnregister(uint64_t executorIndex) override;
    void SetIsReady(bool isReady);
    void SetAccessTokenReady(bool isReady);

protected:
    void OnStart() override;
    void OnStop() override;

private:
    static void Init();
    static void AddExecutorDeathRecipient(uint64_t executorIndex, AuthType authType,
        std::shared_ptr<ExecutorCallbackInterface> callback);
    void AuthServiceInit();
    ResultCode RegisterAccessTokenListener();
    ResultCode UnRegisterAccessTokenListener();
    void NotifyFwkReady();
    bool IsFwkReady();

    static std::shared_ptr<CoAuthService> instance_;
    std::recursive_mutex mutex_;
    bool isReady_{false};
    bool accessTokenReady_{false};
    sptr<SystemAbilityListener> accessTokenListener_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_SERVICE_H