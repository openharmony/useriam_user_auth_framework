/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef LOAD_MODE_UTIL_H
#define LOAD_MODE_UTIL_H

#include <string>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
inline const std::string ACCESS_USER_AUTH_INTERNAL_PERMISSION = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
inline const std::string ACCESS_BIOMETRIC_PERMISSION = "ohos.permission.ACCESS_BIOMETRIC";
inline const std::string MANAGE_USER_IDM_PERMISSION = "ohos.permission.MANAGE_USER_IDM";
inline const std::string USE_USER_IDM_PERMISSION = "ohos.permission.USE_USER_IDM";
class LoadModeUtil {
public:
    static int32_t GetProxyNullResultCode(const char *funcName, const std::vector<std::string> &permissions);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // LOAD_MODE_UTIL_H