/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "ipc_common.h"
#include "widget_schedule_node_impl.h"

#include <future>
#include "iam_check.h"
#include "widget_json.h"
#include "widget_callback_interface.h"

#include "mock_authentication.h"
#include "mock_context.h"
#include "user_auth_service.h"

#include "mock_resource_node.h"
#include "mock_schedule_node.h"
#include "schedule_node_impl.h"
#include "user_auth_callback_proxy.h"
#include "widget_schedule_node.h"


using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace UserIam {
namespace UserAuth {

class IpcCommonTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};

void IpcCommonTest::SetUpTestCase()
{
}

void IpcCommonTest::TearDownTestCase()
{
}

void IpcCommonTest::SetUp()
{
}

void IpcCommonTest::TearDown()
{
}

HWTEST_F(IpcCommonTest, IpcCommonTestGetTokenId, TestSize.Level0)
{
    UserAuthService service(100, true);
    service.Notice(NoticeType::WIDGET_NOTICE, "PIN");
    EXPECT_NE(IpcCommon::GetTokenId(service), (uint32_t)0);
}
}
}
}