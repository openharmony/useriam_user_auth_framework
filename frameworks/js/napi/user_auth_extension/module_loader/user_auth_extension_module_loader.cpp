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

#include "user_auth_extension_module_loader.h"
#include "user_auth_extension.h"

namespace OHOS::AbilityRuntime {
namespace {
constexpr static char USER_AUTH_EXTENSION_NAME[] = "UserAuthExtensionAbility";
constexpr static char USER_AUTH_EXTENSION_TYPE[] = "300";
}

UserAuthExtensionModuleLoader::UserAuthExtensionModuleLoader() = default;
UserAuthExtensionModuleLoader::~UserAuthExtensionModuleLoader() = default;

Extension *UserAuthExtensionModuleLoader::Create(const std::unique_ptr<Runtime>& runtime) const
{
    return UserAuthExtension::Create(runtime);
}

std::map<std::string, std::string> UserAuthExtensionModuleLoader::GetParams()
{
    std::map<std::string, std::string> params;
    // type means extension type in ExtensionAbilityType of extension_ability_info.h, 300 means UserAuthExtension.
    params.insert(std::pair<std::string, std::string>("type", USER_AUTH_EXTENSION_TYPE));
    // extension name
    params.insert(std::pair<std::string, std::string>("name", USER_AUTH_EXTENSION_NAME));
    return params;
}

extern "C" __attribute__((visibility("default"))) void* OHOS_EXTENSION_GetExtensionModule()
{
    return &UserAuthExtensionModuleLoader::GetInstance();
}
} // namespace OHOS::AbilityRuntime
