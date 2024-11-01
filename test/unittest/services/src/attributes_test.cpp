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

#include "attributes_test.h"

#include <climits>

#include "attributes.h"

#include "iam_logger.h"
#include "securec.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void AttributesTest::SetUpTestCase()
{
}

void AttributesTest::TearDownTestCase()
{
}

void AttributesTest::SetUp()
{
}

void AttributesTest::TearDown()
{
}

HWTEST_F(AttributesTest, AttributesInit, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_EQ(attrs.Serialize().size(), 0U);
}

HWTEST_F(AttributesTest, AttributesSerialize, TestSize.Level0)
{
    const std::vector<Attributes::AttributeKey> desired = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_TEMPLATE_ID_LIST, Attributes::ATTR_REMAIN_TIMES, Attributes::ATTR_FREEZING_TIME,
        Attributes::ATTR_SCHEDULE_ID, Attributes::ATTR_SCHEDULE_MODE};

    Attributes attrs;

    EXPECT_TRUE(attrs.SetBoolValue(Attributes::ATTR_RESULT_CODE, true));
    EXPECT_TRUE(attrs.SetBoolValue(Attributes::ATTR_SIGNATURE, false));
    EXPECT_TRUE(attrs.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, UINT64_MAX));
    EXPECT_TRUE(attrs.SetUint32ArrayValue(Attributes::ATTR_REMAIN_TIMES, {1, 3, 5, 7, 9}));
    EXPECT_TRUE(attrs.SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, UINT32_MAX));
    EXPECT_TRUE(attrs.SetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, {2, 4, 6, 8, 10}));
    EXPECT_TRUE(attrs.SetStringValue(Attributes::ATTR_TEMPLATE_ID_LIST, "iam"));

    EXPECT_THAT(attrs.GetKeys(), ElementsAreArray(desired));
    auto buff = attrs.Serialize();
    Attributes attrs2(buff);
    EXPECT_THAT(attrs2.GetKeys(), ElementsAreArray(desired));

    bool boolValue;
    EXPECT_TRUE(attrs2.GetBoolValue(Attributes::ATTR_RESULT_CODE, boolValue));
    EXPECT_EQ(boolValue, true);

    EXPECT_TRUE(attrs2.GetBoolValue(Attributes::ATTR_SIGNATURE, boolValue));
    EXPECT_EQ(boolValue, false);

    uint64_t u64Value;
    EXPECT_TRUE(attrs2.GetUint64Value(Attributes::ATTR_SCHEDULE_ID, u64Value));
    EXPECT_EQ(u64Value, UINT64_MAX);

    std::vector<uint32_t> u32Vector;
    EXPECT_TRUE(attrs2.GetUint32ArrayValue(Attributes::ATTR_REMAIN_TIMES, u32Vector));
    EXPECT_THAT(u32Vector, ElementsAre(1, 3, 5, 7, 9));

    uint32_t u32Value;
    EXPECT_TRUE(attrs2.GetUint32Value(Attributes::ATTR_SCHEDULE_MODE, u32Value));
    EXPECT_EQ(u32Value, UINT32_MAX);

    std::vector<uint64_t> u64Vector;
    EXPECT_TRUE(attrs2.GetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, u64Vector));
    EXPECT_THAT(u64Vector, ElementsAre(2, 4, 6, 8, 10));

    std::string str;
    EXPECT_TRUE(attrs2.GetStringValue(Attributes::ATTR_TEMPLATE_ID_LIST, str));
    EXPECT_EQ(str, "iam");
}

HWTEST_F(AttributesTest, AttributesBoolValue, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetBoolValue(Attributes::ATTR_RESULT_CODE, true));
    EXPECT_TRUE(attrs.SetBoolValue(Attributes::ATTR_SIGNATURE, false));

    bool value1;
    bool value2;
    EXPECT_TRUE(attrs.GetBoolValue(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetBoolValue(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1);
    EXPECT_FALSE(value2);
}

HWTEST_F(AttributesTest, AttributesUint64Value, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetUint64Value(Attributes::ATTR_RESULT_CODE, UINT32_MAX));
    EXPECT_TRUE(attrs.SetUint64Value(Attributes::ATTR_SIGNATURE, UINT64_MAX));

    uint64_t value1;
    uint64_t value2;
    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, UINT32_MAX);
    EXPECT_EQ(value2, UINT64_MAX);
}

HWTEST_F(AttributesTest, AttributesUint32Value, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetUint32Value(Attributes::ATTR_RESULT_CODE, UINT16_MAX));
    EXPECT_TRUE(attrs.SetUint32Value(Attributes::ATTR_SIGNATURE, UINT32_MAX));

    uint32_t value1;
    uint32_t value2;
    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1 == UINT16_MAX);
    EXPECT_TRUE(value2 == UINT32_MAX);
}

HWTEST_F(AttributesTest, AttributesUint16Value, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetUint16Value(Attributes::ATTR_RESULT_CODE, UINT8_MAX));
    EXPECT_TRUE(attrs.SetUint16Value(Attributes::ATTR_SIGNATURE, UINT16_MAX));

    uint16_t value1;
    uint16_t value2;
    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1 == UINT8_MAX);
    EXPECT_TRUE(value2 == UINT16_MAX);
}

HWTEST_F(AttributesTest, AttributesUint8Value, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetUint8Value(Attributes::ATTR_RESULT_CODE, 0));
    EXPECT_TRUE(attrs.SetUint8Value(Attributes::ATTR_SIGNATURE, UINT8_MAX));

    uint8_t value1;
    uint8_t value2;
    EXPECT_TRUE(attrs.GetUint8Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetUint8Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, 0);
    EXPECT_EQ(value2, UINT8_MAX);
}

HWTEST_F(AttributesTest, AttributesStringValue, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetStringValue(Attributes::ATTR_RESULT_CODE, "hello iam"));
    EXPECT_TRUE(attrs.SetStringValue(Attributes::ATTR_SIGNATURE, ""));

    std::string value1;
    std::string value2;
    EXPECT_TRUE(attrs.GetStringValue(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetStringValue(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, "hello iam");
    EXPECT_EQ(value2, "");
}

HWTEST_F(AttributesTest, AttributesUint64ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint64_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(UINT64_MAX - i);
        }
        EXPECT_TRUE(attrs.SetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        std::vector<uint64_t> out;
        EXPECT_TRUE(attrs.GetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }

    {
        Attributes attrs;
        std::vector<uint64_t> array;
        EXPECT_TRUE(attrs.SetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(attrs.GetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint32ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint32_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(UINT32_MAX - i);
        }
        EXPECT_TRUE(attrs.SetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        std::vector<uint32_t> out;
        EXPECT_TRUE(attrs.GetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint32_t> array;
        EXPECT_TRUE(attrs.SetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        EXPECT_TRUE(attrs.GetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint16ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint16_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(UINT16_MAX - i);
        }
        EXPECT_TRUE(attrs.SetUint16ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        std::vector<uint16_t> out;
        EXPECT_TRUE(attrs.GetUint16ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint16_t> array;
        EXPECT_TRUE(attrs.SetUint16ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        EXPECT_TRUE(attrs.GetUint16ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint8ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint8_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(i);
        }
        EXPECT_TRUE(attrs.SetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        std::vector<uint8_t> out;
        EXPECT_TRUE(attrs.GetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint8_t> array;
        EXPECT_TRUE(attrs.SetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        EXPECT_TRUE(attrs.GetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesDeserializeMismatch, TestSize.Level0)
{
    const std::vector<uint8_t> raw = {0, 0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5, 0,
        0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0, 40, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0,
        0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 5, 0, 0, 0, 4, 0, 0,
        0, 255, 255, 255, 255, 6, 0, 0, 0, 8, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 7, 0, 0, 0, 4, 0, 0, 0,
        105, 97, 109, 0};

    Attributes attrs(raw);
    {
        bool value;
        EXPECT_FALSE(attrs.GetBoolValue(Attributes::ATTR_TEMPLATE_ID_LIST, value));
    }
    {
        uint16_t value;
        EXPECT_FALSE(attrs.GetUint16Value(Attributes::ATTR_TEMPLATE_ID_LIST, value));
    }
}

HWTEST_F(AttributesTest, AttributesEmptyArrays, TestSize.Level0)
{
    Attributes attrs1;
    bool value = true;
    EXPECT_TRUE(attrs1.SetBoolValue(Attributes::ATTR_RESULT_CODE, value));

    std::vector<uint64_t> u64Vector;
    EXPECT_TRUE(attrs1.SetUint64ArrayValue(Attributes::ATTR_SCHEDULE_ID, u64Vector));

    std::vector<uint32_t> u32Vector;
    EXPECT_TRUE(attrs1.SetUint32ArrayValue(Attributes::ATTR_REMAIN_TIMES, u32Vector));

    std::vector<uint16_t> u16Vector;
    EXPECT_TRUE(attrs1.SetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, u16Vector));

    std::vector<uint8_t> u8Vector;
    EXPECT_TRUE(attrs1.SetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, u8Vector));

    auto buff = attrs1.Serialize();
    EXPECT_FALSE(buff.empty());
    Attributes attrs2(buff);
    EXPECT_TRUE(attrs1.GetBoolValue(Attributes::ATTR_RESULT_CODE, value));
    EXPECT_TRUE(value);

    EXPECT_TRUE(attrs1.GetUint64ArrayValue(Attributes::ATTR_SCHEDULE_ID, u64Vector));
    EXPECT_THAT(u64Vector, IsEmpty());

    EXPECT_TRUE(attrs1.GetUint32ArrayValue(Attributes::ATTR_REMAIN_TIMES, u32Vector));
    EXPECT_THAT(u32Vector, IsEmpty());

    EXPECT_TRUE(attrs1.GetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, u16Vector));
    EXPECT_THAT(u16Vector, IsEmpty());

    EXPECT_TRUE(attrs1.GetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, u8Vector));
    EXPECT_THAT(u8Vector, IsEmpty());
}

HWTEST_F(AttributesTest, AttributesCopyAndMove, TestSize.Level0)
{
    EXPECT_FALSE(std::is_copy_assignable<Attributes>::value);
    EXPECT_FALSE(std::is_copy_constructible<Attributes>::value);

    const std::vector<uint8_t> raw = {0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 255,
        255, 255, 255, 3, 0, 0, 0, 8, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 4, 0, 0, 0, 4, 0, 0, 0, 105, 97,
        109, 0, 5, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 6, 0, 0, 0, 40, 0,
        0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0,
        0, 0, 0, 0, 0};
    Attributes attrs1(raw);

    EXPECT_THAT(attrs1.Serialize(), ElementsAreArray(raw));

    Attributes attrs2 = std::move(attrs1);

    EXPECT_EQ(attrs1.Serialize().size(), 0U);
    EXPECT_THAT(attrs2.Serialize(), ElementsAreArray(raw));
}

HWTEST_F(AttributesTest, AttributesSetAndGetAttributesArray, TestSize.Level0)
{
    Attributes attrs1;
    Attributes attrs2;
    EXPECT_TRUE(attrs1.SetBoolValue(Attributes::ATTR_RESULT_CODE, true));
    EXPECT_TRUE(attrs1.SetBoolValue(Attributes::ATTR_SCHEDULE_ID, false));
    EXPECT_TRUE(attrs2.SetBoolValue(Attributes::ATTR_RESULT_CODE, true));
    EXPECT_TRUE(attrs2.SetBoolValue(Attributes::ATTR_SCHEDULE_ID, false));

    std::vector<Attributes> attrsArray;
    attrsArray.push_back(Attributes(attrs1.Serialize()));
    attrsArray.push_back(Attributes(attrs2.Serialize()));

    Attributes setAttrs;
    EXPECT_TRUE(setAttrs.SetAttributesArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attrsArray));

    std::vector<uint8_t> data = setAttrs.Serialize();
    EXPECT_TRUE(data.size() > 0);

    Attributes getAttrs(data);
    std::vector<Attributes> getAttrsArray;
    EXPECT_TRUE(getAttrs.GetAttributesArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, getAttrsArray));

    ASSERT_EQ(getAttrsArray.size(), 2);
    std::vector<uint8_t> serializedAttrs1 = attrs1.Serialize();
    std::vector<uint8_t> serializedAttrs2 = attrs2.Serialize();

    std::vector<uint8_t> serializedOutAttrs1 = getAttrsArray[0].Serialize();
    std::vector<uint8_t> serializedOutAttrs2 = getAttrsArray[1].Serialize();

    EXPECT_TRUE(serializedAttrs1 == serializedOutAttrs1);
    EXPECT_TRUE(serializedAttrs2 == serializedOutAttrs2);
}

HWTEST_F(AttributesTest, AttributesSetAndGetAttributesArray01, TestSize.Level0)
{
    Attributes attrs1;
    int64_t value1 = 1;
    EXPECT_EQ(attrs1.SetInt64Value(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, value1), true);
    EXPECT_EQ(attrs1.GetInt64Value(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, value1), true);
    EXPECT_EQ(value1, 1);

    Attributes setAttrs;
    EXPECT_EQ(setAttrs.SetAttributesValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attrs1), true);
    Attributes attrs2;
    EXPECT_EQ(setAttrs.GetAttributesValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attrs2), true);

    std::vector<int32_t> array1;
    array1.push_back(1);
    EXPECT_EQ(setAttrs.SetInt32ArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, array1), true);
    std::vector<int32_t> array2;
    EXPECT_EQ(setAttrs.GetInt32ArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, array2), true);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
