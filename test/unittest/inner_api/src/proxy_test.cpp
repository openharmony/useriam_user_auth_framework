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

#include "proxy_test.h"

#include "mock_remote_object.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void ProxyTest::SetUpTestCase()
{
}

void ProxyTest::TearDownTestCase()
{
}

void ProxyTest::SetUp()
{
}

void ProxyTest::TearDown()
{
}

HWTEST_F(ProxyTest, ProxyGetAvailableStatus, TestSize.Level0)
{
    sptr<IRemoteObject> obj = new MockRemoteObject();
    EXPECT_NE(obj, nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS