/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

/**
 * @file attributes.h
 *
 * @brief Attributes enum define.
 * @since 3.1
 * @version 3.2
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
    /**
     * @brief The key to set attribute.
     */
    enum AttributeKey : uint32_t {
        /** Root tag. */
        ATTR_ROOT = 100000,
        /** Result code, the value type is int32_t. */
        ATTR_RESULT_CODE = 100001,
        /** Signature, the value type is std::vector<uint8_t>. */
        ATTR_SIGNATURE = 100004,
        /** Identify mode, the value type is uint32_t. */
        ATTR_IDENTIFY_MODE = 100005,
        /** Template ID, the value type is uint64_t. */
        ATTR_TEMPLATE_ID = 100006,
        /** Template ID list, the value type is std::vector<uint64_t>. */
        ATTR_TEMPLATE_ID_LIST = 100007,
        /** Attribute error count, the value type is int32_t. */
        ATTR_ERROR_COUNT = 100008,
        /** Remain time, the value type is int32_t. */
        ATTR_REMAIN_TIMES = 100009,
        /** Freezing time, the value type is int32_t. */
        ATTR_FREEZING_TIME = 100010,
        /** Session ID, the value type is uint64_t. */
        ATTR_SESSION_ID = 100014,
        /** Schedule version, the value type is uint32_t. */
        ATTR_SCHEDULE_VERSION = 100016,
        /** Schedule ID, the value type is uint64_t. */
        ATTR_SCHEDULE_ID = 100020,
        /** Pin subtype, the value type is int32_t. */
        ATTR_PIN_SUB_TYPE = 100021,
        /** Schedule mode, the value type is int32_t. */
        ATTR_SCHEDULE_MODE = 100022,
        /** Property mode, the value type is uint32_t. */
        ATTR_PROPERTY_MODE = 100023,
        /** Authenticate type, the value type is int32_t. */
        ATTR_AUTH_TYPE = 100024,
        /** Credential ID, the value type is uint64_t. */
        ATTR_CREDENTIAL_ID = 100025,
        /** Caller UID, the value type is uint64_t. */
        ATTR_CALLER_UID = 100027,
        /** Tag of result, the value type is std::vector<uint8_t>. */
        ATTR_RESULT = 100028,
        /** Capability level, the value type is uint64_t. */
        ATTR_CAPABILITY_LEVEL = 100029,
        /** Algorithm infomation, the value type is uint64_t. */
        ATTR_ALGORITHM_INFO = 100030,
        /** Timer stamp, the value type is uint64_t. */
        ATTR_TIME_STAMP = 100031,
        /** Root secret, the value type is std::vector<uint8_t>. */
        ATTR_ROOT_SECRET = 100032,
        /** Auth token, the value type is std::vector<uint8_t>. */
        ATTR_AUTH_TOKEN = 100033,
        /** Security user id return when add pin credential, the value type is uint64_t. */
        ATTR_SEC_USER_ID = 100034,
        /** Enroll progress, the value type is string. */
        ATTR_ENROLL_PROGRESS = 100035,
        /** Sensor info, the value type is string. */
        ATTR_SENSOR_INFO = 100036,
        /** Key list, the value type is std::vector<uint32_t>. */
        ATTR_KEY_LIST = 100037,
        /** End after first fail, the value type is boolean. */
        ATTR_END_AFTER_FIRST_FAIL = 100038,
        /** tip info, the value type is int32_t. */
        ATTR_TIP_INFO = 100039,
        /** Old root secret, the value type is std::vector<uint8_t>. */
        ATTR_OLD_ROOT_SECRET = 100040,
        /** Old credential ID, the value type is uint64_t. */
        ATTR_OLD_CREDENTIAL_ID = 100041,
        /**
         * Private attrs.
         * User ID, the value type is int32_t.
         */
        ATTR_USER_ID = 300000,
        /** Extra infomation, the value type is std::vector<uint8_t>. */
        ATTR_EXTRA_INFO,
        /** Executor ID, the value type is uint64_t. */
        ATTR_EXECUTOR_INDEX,
        /** ExecutorSensorHint, the value type is uint32_t. */
        ATTR_EXECUTOR_SENSOR_HINT,
        /** ExecutorMatcher, the value type is uint32_t. */
        ATTR_EXECUTOR_MATCHER,
        /** Access token ID, the value type is uint32_t. */
        ATTR_ACCESS_TOKEN_ID,
        /** Template change reason, the value type is string */
        ATTR_TEMPLATE_CHANGE_REASON,
        /** Credential digest, the value type is uint16_t. */
        ATTR_CREDENTIAL_DIGEST,
        /** Credential count, the value type is uint16_t. */
        ATTR_CREDENTIAL_COUNT,
    };

    /**
     * @brief Default constructor.
     */
    Attributes();

    /**
     * @brief Overload constructor.
     *
     * This constructor prohibits implicit type conversion of input parameters.
     *
     * @param raw The value to be passed in when defining Attribute.
     */
    explicit Attributes(const std::vector<uint8_t> &raw);

    /**
     * @brief Overload constructor.
     *
     * This constructor is used to define constant Attribute type.
     *
     * @param other The value to be passed in when defining Attribute.
     */
    Attributes(const Attributes &other) = delete;

    /**
     * @brief Overload operator.
     *
     * @param other The value to be compared.
     */
    Attributes &operator=(const Attributes &other) = delete;

    /**
     * @brief Overload constructor.
     *
     * @param other The value to be passed in when defining Attribute.
     */
    Attributes(Attributes &&other) noexcept;

    /**
     * @brief Overload operator.
     *
     * @param other The value to be compared.
     */
    Attributes &operator=(Attributes &&other) noexcept;

    /**
     * @brief Deconstructor.
     */
    virtual ~Attributes();

    /**
     * @brief Set bool value.
     *
     * @param key The attribute key.
     * @param value The bool value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetBoolValue(AttributeKey key, bool value);

    /**
     * @brief Set uint64 value.
     *
     * @param key The attribute key.
     * @param value The uint64_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint64Value(AttributeKey key, uint64_t value);

    /**
     * @brief Set uint32_t value.
     *
     * @param key The attribute key.
     * @param value The uint32_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint32Value(AttributeKey key, uint32_t value);

    /**
     * @brief Set uint16_t value.
     *
     * @param key The attribute key.
     * @param value The uint16_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint16Value(AttributeKey key, uint16_t value);

    /**
     * @brief Set uint8_t value.
     *
     * @param key The attribute key.
     * @param value The uint8_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint8Value(AttributeKey key, uint8_t value);

    /**
     * @brief Set int32_t value.
     *
     * @param key The attribute key.
     * @param value The int32_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetInt32Value(AttributeKey key, int32_t value);

    /**
     * @brief Set string value.
     *
     * @param key The attribute key.
     * @param value The string.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetStringValue(AttributeKey key, const std::string &value);

    /**
     * @brief Set Attributes value.
     *
     * @param key The attribute key.
     * @param value The attributes type value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetAttributesValue(AttributeKey key, const Attributes &value);

    /**
     * @brief Set vector<uint64_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint64_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value);

    /**
     * @brief Set vector<uint32_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint32_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value);

    /**
     * @brief Set vector<uint16_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint16_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value);

    /**
     * @brief Set vector<uint8_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint8_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value);

    /**
     * @brief Get bool value.
     *
     * @param key The attribute key.
     * @param value Return bool value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetBoolValue(AttributeKey key, bool &value) const;

    /**
     * @brief Get uint64_t value.
     *
     * @param key The attribute key.
     * @param value Return uint64_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint64Value(AttributeKey key, uint64_t &value) const;

    /**
     * @brief Get uint32_t value.
     *
     * @param key The attribute key.
     * @param value Return uint32_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint32Value(AttributeKey key, uint32_t &value) const;

    /**
     * @brief Get uint16_t value.
     *
     * @param key The attribute key.
     * @param value Return uint16_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint16Value(AttributeKey key, uint16_t &value) const;

    /**
     * @brief Get uint8_t value.
     *
     * @param key The attribute key.
     * @param value Return uint8_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint8Value(AttributeKey key, uint8_t &value) const;

    /**
     * @brief Get int32_t value.
     *
     * @param key The attribute key.
     * @param value Return int32_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetInt32Value(AttributeKey key, int32_t &value) const;

    /**
     * @brief Get string value.
     *
     * @param key The attribute key.
     * @param value Return string corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetStringValue(AttributeKey key, std::string &value) const;

    /**
     * @brief Get vector<uint64_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint64_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const;

    /**
     * @brief Get vector<uint32_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint32_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const;

    /**
     * @brief Get vector<uint16_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint16_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const;

    /**
     * @brief Get vector<uint8_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint8_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const;

    /**
     * @brief Get Attributes value.
     *
     * @param key The attribute key.
     * @param value Return Attributes value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetAttributesValue(AttributeKey key, Attributes &value) const;

    /**
     * @brief Serialize the Attribute object.
     *
     * @return Return serialized Attribute object.
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * @brief Get all keys of Attribute.
     *
     * @return Return all keys of Attribute.
     */
    std::vector<AttributeKey> GetKeys() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_ATTRIBUTES_H
