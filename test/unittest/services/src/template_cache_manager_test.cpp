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
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

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

using OsAccountSubscriber = AccountSA::OsAccountSubscriber;
using OsAccountSubscribeInfo = AccountSA::OsAccountSubscribeInfo;
using OS_ACCOUNT_SUBSCRIBE_TYPE = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE;

class ServiceStatusListener : public OHOS::SystemAbilityStatusChangeStub, public NoCopyable {
public:
    static sptr<ServiceStatusListener> GetInstance();
    static void Subscribe();

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    ServiceStatusListener() {};
    ~ServiceStatusListener() override {};
};

class OsAccountIdSubscriber : public OsAccountSubscriber, public NoCopyable {
public:
    explicit OsAccountIdSubscriber(const OsAccountSubscribeInfo &subscribeInfo);
    ~OsAccountIdSubscriber() = default;

    static std::shared_ptr<OsAccountIdSubscriber> GetInstance();
    static void Subscribe();
    static void Unsubscribe();
    void OnAccountsChanged(const int& id) override;
};

HWTEST_F(TemplateCacheManagerTest, TemplateCacheManagerTest_001, TestSize.Level1)
{
    EXPECT_NO_THROW({
        TemplateCacheManager::GetInstance().UpdateTemplateCache(PIN);
        TemplateCacheManager::GetInstance().ProcessUserIdChange(1);
        TemplateCacheManager::GetInstance().ProcessUserIdChange(1);
        TemplateCacheManager::GetInstance().UpdateTemplateCache(PIN);
    });
}

HWTEST_F(TemplateCacheManagerTest, TemplateCacheManagerTestOnAddSystemAbility, TestSize.Level1)
{
    int32_t systemAbilityId = 1;
    const std::string deviceId = "123";
    EXPECT_NO_THROW({
        ServiceStatusListener::GetInstance()->OnAddSystemAbility(systemAbilityId, deviceId);
    });
}

HWTEST_F(TemplateCacheManagerTest, TemplateCacheManagerTestOnRemoveSystemAbility_001, TestSize.Level1)
{
    int32_t systemAbilityId = 1;
    const std::string deviceId = "123";
    EXPECT_NO_THROW({
        ServiceStatusListener::GetInstance()->OnRemoveSystemAbility(systemAbilityId, deviceId);
    });
}

HWTEST_F(TemplateCacheManagerTest, TemplateCacheManagerTestOnRemoveSystemAbility_002, TestSize.Level1)
{
    int32_t systemAbilityId = 200;
    const std::string deviceId = "123";
    EXPECT_NO_THROW({
        ServiceStatusListener::GetInstance()->OnAddSystemAbility(systemAbilityId, deviceId);
    });
}

HWTEST_F(TemplateCacheManagerTest, TemplateCacheManagerTestUnsubscribe, TestSize.Level1)
{
    EXPECT_NO_THROW({
        OsAccountIdSubscriber::GetInstance()->Unsubscribe();
    });
}

HWTEST_F(TemplateCacheManagerTest, TemplateCacheManagerTestOnAccountsChanged, TestSize.Level1)
{
    const int id = 1;
    EXPECT_NO_THROW({
        OsAccountIdSubscriber::GetInstance()->OnAccountsChanged(id);
    });
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS