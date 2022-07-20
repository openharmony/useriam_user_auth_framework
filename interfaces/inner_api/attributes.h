/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef IAM_ATTRIBUTES_H
#define IAM_ATTRIBUTES_H

#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Attributes final {
public:
    enum AttributeKey : uint32_t {
        ATTR_ROOT = 100000,
        ATTR_RESULT_CODE = 100001,
        ATTR_SIGNATURE = 100004,
        ATTR_IDENTIFY_MODE = 100005,
        ATTR_TEMPLATE_ID = 100006,
        ATTR_TEMPLATE_ID_LIST = 100007,
        ATTR_ERROR_COUNT = 100008,
        ATTR_REMAIN_TIMES = 100009,
        ATTR_FREEZING_TIME = 100010,
        ATTR_SESSION_ID = 100014,
        ATTR_SCHEDULE_VERSION = 100016,
        ATTR_SCHEDULE_ID = 100020,
        ATTR_PIN_SUB_TYPE = 100021,
        ATTR_SCHEDULE_MODE = 100022,
        ATTR_PROPERTY_MODE = 100023,
        ATTR_AUTH_TYPE = 100024,
        ATTR_CREDENTIAL_ID = 100025,
        ATTR_CALLER_UID = 100027,
        ATTR_RESULT = 100028,
        ATTR_CAPABILITY_LEVEL = 100029,
        ATTR_ALGORITHM_INFO = 100030,
        ATTR_TIME_STAMP = 100031,
        ATTR_ROOT_SECRET = 100032,
        ATTR_AUTH_TOKEN = 100033,

        // private attrs
        ATTR_USER_ID = 300000,
        ATTR_EXTRA_INFO,
        ATTR_EXECUTOR_INDEX,
        ATTR_EXECUTOR_SENSOR_HINT,
        ATTR_EXECUTOR_MATCHER,
        ATTR_ACCESS_TOKEN_ID,
    };

    Attributes();

    explicit Attributes(const std::vector<uint8_t> &raw);

    Attributes(const Attributes &other) = delete;
    Attributes &operator=(const Attributes &other) = delete;

    Attributes(Attributes &&other) noexcept;
    Attributes &operator=(Attributes &&other) noexcept;

    virtual ~Attributes();

    bool SetBoolValue(AttributeKey key, bool value);
    bool SetUint64Value(AttributeKey key, uint64_t value);
    bool SetUint32Value(AttributeKey key, uint32_t value);
    bool SetUint16Value(AttributeKey key, uint16_t value);
    bool SetUint8Value(AttributeKey key, uint8_t value);
    bool SetInt32Value(AttributeKey key, int32_t value);
    bool SetStringValue(AttributeKey key, const std::string &value);
    bool SetAttributesValue(AttributeKey key, const Attributes &value);
    bool SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value);
    bool SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value);
    bool SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value);
    bool SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value);

    bool GetBoolValue(AttributeKey key, bool &value) const;
    bool GetUint64Value(AttributeKey key, uint64_t &value) const;
    bool GetUint32Value(AttributeKey key, uint32_t &value) const;
    bool GetUint16Value(AttributeKey key, uint16_t &value) const;
    bool GetUint8Value(AttributeKey key, uint8_t &value) const;
    bool GetInt32Value(AttributeKey key, int32_t &value) const;
    bool GetStringValue(AttributeKey key, std::string &value) const;
    bool GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const;
    bool GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const;
    bool GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const;
    bool GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const;
    bool GetAttributesValue(AttributeKey key, Attributes &value) const;
    std::vector<uint8_t> Serialize() const;
    std::vector<AttributeKey> GetKeys() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_ATTRIBUTES_H
