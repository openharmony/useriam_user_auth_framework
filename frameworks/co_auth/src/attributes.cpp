/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "attributes.h"

#include <memory>

#include "iam_logger.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA
Attributes::Attributes(const std::vector<uint8_t> &raw)
{
    std::map<AttributeKey, const std::vector<uint8_t>> out;

    const uint8_t *curr = &raw.front();
    const uint8_t *end = &raw.back() + sizeof(uint8_t);
    while (curr < end) {
        if (curr + sizeof(uint32_t) + sizeof(uint32_t) < curr) { // in case of out of range
            IAM_LOGE("out of pointer range");
            return;
        }

        if (curr + sizeof(uint32_t) + sizeof(uint32_t) > end) {
            IAM_LOGE("out of end range");
            return;
        }

        uint32_t type;
        if (memcpy_s(&type, sizeof(uint32_t), curr, sizeof(uint32_t)) != EOK) {
            IAM_LOGE("type copy error");
            return;
        }
        curr += sizeof(uint32_t);

        uint32_t length;
        if (memcpy_s(&length, sizeof(uint32_t), curr, sizeof(uint32_t)) != EOK) {
            IAM_LOGE("length copy error");
            return;
        }
        curr += sizeof(uint32_t);

        if (length % sizeof(uint8_t) != 0 || length > MAX_ATTR_LENGTH) {
            IAM_LOGE("length format error, length = %{public}u", length);
            return;
        }

        if (length > end - curr) {
            IAM_LOGE("length too big, length = %{public}u", length);
            return;
        }

        std::vector<uint8_t> value(length / sizeof(uint8_t));
        if (length != 0 && memcpy_s(value.data(), value.size() * sizeof(uint8_t), curr, length) != EOK) {
            IAM_LOGE("value copy error, length = %{public}u", length);
            return;
        }

        auto ret = out.try_emplace(static_cast<AttributeKey>(type), value);
        if (!ret.second) {
            IAM_LOGE("emplace pair error, type is %{public}u", type);
            return;
        }

        if (out.size() > MAX_ATTR_COUNT) {
            IAM_LOGE("emplace pair error, size reach max");
            return;
        }

        IAM_LOGD("emplace pair success, type is %{public}u", type);
        curr += length;
    }

    map_.swap(out);
}

Attributes::Attributes(Attributes &&other) noexcept : map_(std::move(other.map_))
{
}

Attributes &Attributes::operator=(Attributes &&other) noexcept
{
    map_ = std::move(other.map_);
    return *this;
}

bool Attributes::SetBoolValue(AttributeKey key, bool value)
{
    std::vector<uint8_t> dest;
    if (!EncodeBoolValue(value, dest)) {
        IAM_LOGE("EncodeBoolValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetUint64Value(AttributeKey key, uint64_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint64Value(value, dest)) {
        IAM_LOGE("EncodeUint64Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetUint32Value(AttributeKey key, uint32_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint32Value(value, dest)) {
        IAM_LOGE("EncodeUint32Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetUint16Value(AttributeKey key, uint16_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint16Value(value, dest)) {
        IAM_LOGE("EncodeUint16Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetUint8Value(AttributeKey key, uint8_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint8Value(value, dest)) {
        IAM_LOGE("EncodeUint8Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetInt32Value(AttributeKey key, int32_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeInt32Value(value, dest)) {
        IAM_LOGE("EncodeInt32Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetStringValue(AttributeKey key, const std::string &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeStringValue(value, dest)) {
        IAM_LOGE("EncodeStringValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint64ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint64ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint32ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint32ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint16ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint16ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint8ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint8ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, value);
    return ret.second;
}

bool Attributes::SetAttributesValue(AttributeKey key, const Attributes &value)
{
    std::vector<uint8_t> dest = value.Serialize();
    if (dest.empty()) {
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::GetBoolValue(AttributeKey key, bool &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeBoolValue(iter->second, value)) {
        IAM_LOGE("DecodeBoolValue error");
        return false;
    }

    return true;
}

bool Attributes::GetUint64Value(AttributeKey key, uint64_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint64Value(iter->second, value)) {
        IAM_LOGE("DecodeUint64Value error");
        return false;
    }

    return true;
}

bool Attributes::GetUint32Value(AttributeKey key, uint32_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint32Value(iter->second, value)) {
        IAM_LOGE("DecodeUint32Value error");
        return false;
    }

    return true;
}

bool Attributes::GetUint16Value(AttributeKey key, uint16_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint16Value(iter->second, value)) {
        IAM_LOGE("DecodeUint16Value error");
        return false;
    }

    return true;
}

bool Attributes::GetUint8Value(AttributeKey key, uint8_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint8Value(iter->second, value)) {
        IAM_LOGE("DecodeUint8Value error");
        return false;
    }

    return true;
}

bool Attributes::GetInt32Value(AttributeKey key, int32_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeInt32Value(iter->second, value)) {
        IAM_LOGE("DecodeInt32Value error");
        return false;
    }

    return true;
}

bool Attributes::GetStringValue(AttributeKey key, std::string &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeStringValue(iter->second, value)) {
        IAM_LOGE("DecodeStringValue error");
        return false;
    }

    return true;
}

bool Attributes::GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint64ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint64ArrayValue error");
        return false;
    }

    return true;
}

bool Attributes::GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint32ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint32ArrayValue error");
        return false;
    }

    return true;
}

bool Attributes::GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint16ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint16ArrayValue error");
        return false;
    }

    return true;
}

bool Attributes::GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint8ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint8ArrayValue error");
        return false;
    }
    return true;
}

bool Attributes::GetAttributesValue(AttributeKey key, Attributes &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    Attributes out(iter->second);
    value = std::move(out);
    return true;
}

std::vector<uint8_t> Attributes::Serialize() const
{
    uint32_t size = 0;
    for (const auto &[key, value] : map_) {
        size += sizeof(uint32_t) / sizeof(uint8_t);
        size += sizeof(uint32_t) / sizeof(uint8_t);
        size += value.size();
    }
    std::vector<uint8_t> buffer;
    buffer.reserve(size);

    for (const auto &[key, value] : map_) {
        std::vector<uint8_t> type;
        std::vector<uint8_t> length;
        if (!EncodeUint32Value(key, type)) {
            buffer.clear();
            IAM_LOGE("EncodeUint32Value key error");
            break;
        }
        if (!EncodeUint32Value(value.size() * sizeof(uint8_t), length)) {
            buffer.clear();
            IAM_LOGE("EncodeUint32Value value error");
            break;
        }
        buffer.insert(buffer.end(), type.begin(), type.end());
        buffer.insert(buffer.end(), length.begin(), length.end());
        buffer.insert(buffer.end(), value.begin(), value.end());
    }
    return buffer;
}

std::vector<Attributes::AttributeKey> Attributes::GetKeys() const
{
    std::vector<AttributeKey> keys;
    keys.reserve(map_.size());
    for (auto const &item : map_) {
        keys.push_back(item.first);
    }
    return keys;
}

bool Attributes::EncodeBoolValue(bool src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(1); // only 1
    out[0] = src ? 1 : 0;

    dst.swap(out);
    return true;
}

bool Attributes::EncodeUint64Value(uint64_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(uint64_t) / sizeof(uint8_t));
    if (memcpy_s(out.data(), out.size(), &src, sizeof(src)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::EncodeUint32Value(uint32_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(uint32_t) / sizeof(uint8_t));
    if (memcpy_s(out.data(), out.size(), &src, sizeof(src)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::EncodeUint16Value(uint16_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(uint16_t) / sizeof(uint8_t));
    if (memcpy_s(out.data(), out.size(), &src, sizeof(src)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::EncodeUint8Value(uint8_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(1);
    out[0] = src;
    dst.swap(out);
    return true;
}

bool Attributes::EncodeInt32Value(int32_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(int32_t) / sizeof(uint8_t));
    if (memcpy_s(out.data(), out.size(), &src, sizeof(src)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::EncodeStringValue(const std::string &src, std::vector<uint8_t> &dst)
{
    if (src.size() > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(src.begin(), src.end());
    out.push_back(0);
    dst.swap(out);
    return true;
}

bool Attributes::EncodeUint64ArrayValue(const std::vector<uint64_t> &src, std::vector<uint8_t> &dst)
{
    auto size = src.size() * (sizeof(uint64_t) / sizeof(uint8_t));
    if (size > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(size);

    if (!src.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint8_t), src.data(), src.size() * sizeof(uint64_t)) != EOK) {
        return false;
    }

    dst.swap(out);
    return true;
}

bool Attributes::EncodeUint32ArrayValue(const std::vector<uint32_t> &src, std::vector<uint8_t> &dst)
{
    auto size = src.size() * (sizeof(uint32_t) / sizeof(uint8_t));
    if (size > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(size);

    if (!src.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint8_t), src.data(), src.size() * sizeof(uint32_t)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::EncodeUint16ArrayValue(const std::vector<uint16_t> &src, std::vector<uint8_t> &dst)
{
    auto size = src.size() * (sizeof(uint16_t) / sizeof(uint8_t));
    if (size > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(size);

    if (!src.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint8_t), src.data(), src.size() * sizeof(uint16_t)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::EncodeUint8ArrayValue(const std::vector<uint8_t> &src, std::vector<uint8_t> &dst)
{
    if (src.size() > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(src);
    dst.swap(out);
    return true;
}

bool Attributes::DecodeBoolValue(const std::vector<uint8_t> &src, bool &dst)
{
    if (src.size() != 1) {
        return false;
    }
    dst = (src[0] == 1);
    return true;
}

bool Attributes::DecodeUint64Value(const std::vector<uint8_t> &src, uint64_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(uint64_t)) {
        return false;
    }

    if (memcpy_s(&dst, sizeof(dst), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    return true;
}

bool Attributes::DecodeUint32Value(const std::vector<uint8_t> &src, uint32_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(uint32_t)) {
        return false;
    }
    if (memcpy_s(&dst, sizeof(dst), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    return true;
}

bool Attributes::DecodeUint16Value(const std::vector<uint8_t> &src, uint16_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(uint16_t)) {
        return false;
    }
    if (memcpy_s(&dst, sizeof(dst), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    return true;
}

bool Attributes::DecodeUint8Value(const std::vector<uint8_t> &src, uint8_t &dst)
{
    if (src.size() != 1) {
        return false;
    }
    dst = src[0];
    return true;
}

bool Attributes::DecodeInt32Value(const std::vector<uint8_t> &src, int32_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(int32_t)) {
        return false;
    }
    if (memcpy_s(&dst, sizeof(dst), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    return true;
}

bool Attributes::DecodeStringValue(const std::vector<uint8_t> &src, std::string &dst)
{
    if (src.empty()) {
        return false;
    }

    if (src.back() != 0) {
        return false;
    }

    std::string out(static_cast<const char *>(static_cast<const void *>(src.data())));

    dst.swap(out);
    return true;
}

bool Attributes::DecodeUint64ArrayValue(const std::vector<uint8_t> &src, std::vector<uint64_t> &dst)
{
    if (src.size() % (sizeof(uint64_t) / sizeof(uint8_t)) != 0) {
        return false;
    }

    std::vector<uint64_t> out(src.size() / (sizeof(uint64_t) / sizeof(uint8_t)));

    if (!out.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint64_t), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }

    dst.swap(out);
    return true;
}

bool Attributes::DecodeUint32ArrayValue(const std::vector<uint8_t> &src, std::vector<uint32_t> &dst)
{
    if (src.size() % (sizeof(uint32_t) / sizeof(uint8_t)) != 0) {
        return false;
    }

    std::vector<uint32_t> out(src.size() / (sizeof(uint32_t) / sizeof(uint8_t)));

    if (!out.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint32_t), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }

    dst.swap(out);
    return true;
}

bool Attributes::DecodeUint16ArrayValue(const std::vector<uint8_t> &src, std::vector<uint16_t> &dst)
{
    if (src.size() % (sizeof(uint32_t) / sizeof(uint16_t)) != 0) {
        return false;
    }

    std::vector<uint16_t> out(src.size() / (sizeof(uint16_t) / sizeof(uint8_t)));

    if (!out.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint16_t), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }

    dst.swap(out);
    return true;
}

bool Attributes::DecodeUint8ArrayValue(const std::vector<uint8_t> &src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(src);
    dst.swap(out);
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
