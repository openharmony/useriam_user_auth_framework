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

#ifndef IAM_USER_IDM_CONTROLLER_IMPL_H
#define IAM_USER_IDM_CONTROLLER_IMPL_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include "user_idm_session_controller.h"

#include "singleton.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserIdmSessionControllerImpl : public UserIdmSessionController, public Singleton<UserIdmSessionControllerImpl> {
public:
    bool OpenSession(int32_t userId, std::vector<uint8_t> &challenge) override;
    bool CloseSession(int32_t userId) override;
    bool IsSessionOpened(int32_t userId) const override;
    bool ForceReset() override;

private:
    mutable std::mutex mutex_;
    std::set<int32_t> sessionSet_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_USER_IDM_CONTROLLER_H