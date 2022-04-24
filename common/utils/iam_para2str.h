/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IAM_PARA2STR_H
#define IAM_PARA2STR_H

#include <cinttypes>
#include <cstdint>
#include <string>

namespace OHOS {
namespace UserIAM {
namespace Common {
using namespace std;
const uint64_t UINT64_MASK = 0xffff;
const size_t MASKED_STRING_LEN = 11;
static inline std::string GetMaskedString(uint64_t val)
{
    char bytes[MASKED_STRING_LEN] = {0};
    if (std::snprintf(bytes, sizeof(bytes), "0xXXXX%04" PRIx64, val & UINT64_MASK) == 0) {
        return "(snprintf fail)";
    }
    return std::string(bytes);
}

static inline std::string GetPointerNullStateString(void *p)
{
    if (p == nullptr) {
        return "null";
    }
    return "non-null";
}
} // namespace Common
} // namespace UserIAM
} // namespace OHOS

#endif // IAM_PARA2STR_H