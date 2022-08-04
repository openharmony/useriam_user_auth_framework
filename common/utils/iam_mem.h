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

#ifndef IAM_MEM_H
#define IAM_MEM_H

#include <cstdint>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace Common {
template <typename T>
inline void Pack(std::vector<uint8_t> &dst, const T &data)
{
    const uint8_t *src = static_cast<const uint8_t *>(static_cast<const void *>(&data));
    dst.insert(dst.end(), src, src + sizeof(T));
}

int32_t UnpackUint64(const std::vector<uint8_t> &src, size_t index, uint64_t &data);
int32_t UnpackInt32(const std::vector<uint8_t> &src, size_t index, int32_t &data);

inline uint32_t CombineUint16ToUint32(uint16_t upper, uint16_t lower)
{
    return (static_cast<uint32_t>(upper) << 16U) | lower;
}
} // namespace Common
} // namespace UserIam
} // namespace OHOS

#endif // IAM_MEM_H