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

#include "template_cache_manager_test.h"

#include "iam_common_defines.h"
#include "template_cache_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void TemplateCacheManagerTest::SetUpTestCase()
{
}

void TemplateCacheManagerTest::TearDownTestCase()
{
}

void TemplateCacheManagerTest::SetUp()
{
}

void TemplateCacheManagerTest::TearDown()
{
}

HWTEST_F(TemplateCacheManagerTest, TemplateCacheManagerTest_001, TestSize.Level0)
{
    EXPECT_NO_THROW({
        TemplateCacheManager::GetInstance().UpdateTemplateCache(PIN);
        TemplateCacheManager::GetInstance().ProcessUserIdChange(1);
        TemplateCacheManager::GetInstance().ProcessUserIdChange(1);
        TemplateCacheManager::GetInstance().UpdateTemplateCache(PIN);
    });
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS