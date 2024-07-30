/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_JS_USER_AUTH_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_JS_USER_AUTH_EXTENSION_H

#include <unordered_set>

#include "configuration.h"
#include "user_auth_extension.h"

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class UserAuthExtension;
class JsRuntime;
/**
 * @brief Basic ui extension components.
 */
class JsUserAuthExtension : public UserAuthExtension, public std::enable_shared_from_this<JsUserAuthExtension> {
public:
    explicit JsUserAuthExtension(const std::unique_ptr<Runtime> &runtime);
    virtual ~JsUserAuthExtension() override;

    /**
     * @brief Create JsUserAuthExtension.
     *
     * @param runtime The runtime.
     * @return The JsUserAuthExtension instance.
     */
    static JsUserAuthExtension *Create(const std::unique_ptr<Runtime> &runtime);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_JS_USER_AUTH_EXTENSION_H
