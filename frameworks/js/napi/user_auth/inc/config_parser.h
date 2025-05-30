/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_CONFIG_PARSER_H
#define USER_AUTH_CONFIG_PARSER_H

#include <nlohmann/json.hpp>
#include <string>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ConfigParser {
public:
    ConfigParser() = default;
    ~ConfigParser() = default;

    bool Load(const std::string &configPath);
    std::string Get(const std::string &key, const std::string &defaultValue = "") const;

private:
    nlohmann::json configJson_;
    bool isLoaded_ = false;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_CONFIG_PARSER_H