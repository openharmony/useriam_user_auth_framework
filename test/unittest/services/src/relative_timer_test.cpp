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

#include "relative_timer_test.h"

#include <chrono>
#include <future>

#include "relative_timer.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void RelativeTimerTest::SetUpTestCase()
{
}

void RelativeTimerTest::TearDownTestCase()
{
}

void RelativeTimerTest::SetUp()
{
}

void RelativeTimerTest::TearDown()
{
}

HWTEST_F(RelativeTimerTest, RelativeTimerTest, TestSize.Level0)
{
    using namespace std::chrono;
    std::promise<void> ensure;

    auto &timer = RelativeTimer::GetInstance();
    const time_point<system_clock> start = system_clock::now();
    (void)timer.Register([&ensure]() { ensure.set_value(); }, 565);
    ensure.get_future().get();
    time_point<system_clock> finish = system_clock::now();
    auto cost = duration_cast<milliseconds>(finish - start).count();
    EXPECT_GT(cost, 560);
    EXPECT_LT(cost, 570);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
