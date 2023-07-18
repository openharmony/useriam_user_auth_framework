/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CALLBACK_MANAGER_H
#define CALLBACK_MANAGER_H

#include <cstdint>
#include <functional>

#include "iremote_broker.h"
#include "refbase.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class CallbackManager {
public:
    using CallbackAction = std::function<void()>;
    static CallbackManager &GetInstance();
    virtual ~CallbackManager() = default;
    virtual void AddCallback(uintptr_t key, CallbackAction &action) = 0;
    virtual void RemoveCallback(uintptr_t key) = 0;
    virtual void OnServiceDeath() = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // CALLBACK_MANAGER_H