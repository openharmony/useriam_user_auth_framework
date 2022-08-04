
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

#include "iam_mem.h"

#include <cstdint>
#include <vector>

#include "securec.h"

#define LOG_LABEL LABEL_IAM_COMMON

namespace OHOS {
namespace UserIam {
namespace Common {
int32_t UnpackUint64(const std::vector<uint8_t> &src, size_t index, uint64_t &data)
{
    if ((src.size() < index) || (src.size() - index < sizeof(uint64_t))) {
        return 1;
    }
    if (memcpy_s(static_cast<void *>(&data), sizeof(uint64_t), &src[index], sizeof(uint64_t)) != 0) {
        return 1;
    }
    return 0;
}

int32_t UnpackInt32(const std::vector<uint8_t> &src, size_t index, int32_t &data)
{
    if ((src.size() < index) || (src.size() - index < sizeof(int32_t))) {
        return 1;
    }
    if (memcpy_s(static_cast<void *>(&data), sizeof(int32_t), &src[index], sizeof(int32_t)) != 0) {
        return 1;
    }
    return 0;
}
} // namespace Common
} // namespace UserIam
} // namespace OHOS