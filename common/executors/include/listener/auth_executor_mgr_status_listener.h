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

#ifndef EXECUTOR_MGR_STATUS_LISTENER
#define EXECUTOR_MGR_STATUS_LISTENER

#include <mutex>
#include <set>
#include <string>

#include "nocopyable.h"
#include "refbase.h"

#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthExecutorMgrStatusListener : public OHOS::SystemAbilityStatusChangeStub, public NoCopyable {
public:
    static sptr<AuthExecutorMgrStatusListener> GetInstance();

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    AuthExecutorMgrStatusListener() = default;
    ~AuthExecutorMgrStatusListener() override = default;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // EXECUTOR_MGR_STATUS_LISTENER