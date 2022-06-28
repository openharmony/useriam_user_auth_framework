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

#include "resource_node_test.h"

#include "mock_iuser_auth_interface.h"
#include "mock_resource_node.h"
#include "resource_node.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ResourceNodeTest::SetUpTestCase()
{
}

void ResourceNodeTest::TearDownTestCase()
{
}

void ResourceNodeTest::SetUp()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

void ResourceNodeTest::TearDown()
{
    MockIUserAuthInterface::Holder::GetInstance().Reset();
}

HWTEST_F(ResourceNodeTest, HdiError, TestSize.Level1)
{
    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, AddExecutor(_, _, _, _)).WillRepeatedly(Return(1));
    ExecutorRegisterInfo info {};
    std::vector<uint64_t> templateIdList {};
    std::vector<uint8_t> fwkPublicKey {};

    auto node = ResourceNode::MakeNewResource(info, nullptr, templateIdList, fwkPublicKey);
    EXPECT_EQ(node, nullptr);
}

HWTEST_F(ResourceNodeTest, InsertSuccessWithIndex, TestSize.Level1)
{
    constexpr uint64_t DEST_EXECUTOR_INDEX = 0x12345678;

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, AddExecutor(_, _, _, _)).WillRepeatedly(DoAll(SetArgReferee<1>(DEST_EXECUTOR_INDEX), Return(0)));
    EXPECT_CALL(*mock, DeleteExecutor(DEST_EXECUTOR_INDEX)).Times(Exactly(1)).WillRepeatedly(Return(0));
    {
        ExecutorRegisterInfo info {};
        std::vector<uint64_t> templateIdList {};
        std::vector<uint8_t> fwkPublicKey {};
        auto node = ResourceNode::MakeNewResource(info, nullptr, templateIdList, fwkPublicKey);
        ASSERT_NE(node, nullptr);

        EXPECT_EQ(node->GetExecutorIndex(), DEST_EXECUTOR_INDEX);
    }
}

HWTEST_F(ResourceNodeTest, InsertSuccessWithTemplateIdList, TestSize.Level1)
{
    constexpr uint64_t DEST_EXECUTOR_INDEX = 0x12345678;

    auto fillTemplateIdList = [](std::vector<uint64_t> &list) {
        std::vector<uint64_t> HDI_TEMPLATE_ID_LIST {1, 3, 5, 7, 9};
        list.swap(HDI_TEMPLATE_ID_LIST);
    };

    auto fillFwkPublicKey = [](std::vector<uint8_t> &key) {
        std::vector<uint8_t> FWK_PUB_KEY {5, 3, 7, 1, 4};
        key.swap(FWK_PUB_KEY);
    };

    auto mock = MockIUserAuthInterface::Holder::GetInstance().Get();
    EXPECT_CALL(*mock, AddExecutor(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(DEST_EXECUTOR_INDEX), WithArg<2>(fillFwkPublicKey),
            WithArg<3>(fillTemplateIdList), Return(0)));

    EXPECT_CALL(*mock, DeleteExecutor(DEST_EXECUTOR_INDEX)).Times(Exactly(1)).WillRepeatedly(Return(0));
    {
        ExecutorRegisterInfo info {};
        std::vector<uint64_t> templateIdList {};
        std::vector<uint8_t> fwkPublicKey {};
        auto node = ResourceNode::MakeNewResource(info, nullptr, templateIdList, fwkPublicKey);

        ASSERT_NE(node, nullptr);

        EXPECT_EQ(node->GetExecutorIndex(), DEST_EXECUTOR_INDEX);
        EXPECT_THAT(templateIdList, ElementsAre(1, 3, 5, 7, 9));
        EXPECT_THAT(fwkPublicKey, ElementsAre(5, 3, 7, 1, 4));
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
