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

#ifndef CO_AUTH_SERVICE_H
#define CO_AUTH_SERVICE_H

#include "co_auth_stub.h"

#include <system_ability.h>
#include <system_ability_definition.h>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CoAuthService : public SystemAbility, public CoAuthStub {
public:
    static constexpr uint64_t DEFER_TIME = 2000;
    DECLARE_SYSTEM_ABILITY(CoAuthService);
    explicit CoAuthService(int32_t systemAbilityId, bool runOnCreate = false);
    ~CoAuthService() override = default;
    void OnStart() override;
    void OnStop() override;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    uint64_t ExecutorRegister(const ExecutorRegisterInfo &info, sptr<ExecutorCallbackInterface> &callback) override;

private:
    static void Init();
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // CO_AUTH_SERVICE_H