/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef RELIABILITY_XCOLLIE_HELPER_H
#define RELIABILITY_XCOLLIE_HELPER_H

#include <string>

namespace OHOS {
namespace UserIam {
namespace Common {
constexpr unsigned int API_CALL_TIMEOUT = 20; // 20s

class XCollieHelper {
public:
    XCollieHelper(const std::string &name, unsigned int timeout);
    ~XCollieHelper();

private:
    int id_ = -1;
};
} // namespace Common
} // namespace UserIam
} // namespace OHOS
#endif