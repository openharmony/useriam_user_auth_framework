/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "iam_time.h"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>
#include <sys/types.h>

#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace Common {
const std::string GetNowTimeString()
{
    using namespace std::chrono;
    constexpr uint32_t buffSize = 64;
    constexpr uint32_t dataLen = 19;
    constexpr uint32_t startYear = 1900;
    const time_point<system_clock> now = system_clock::now();
    time_t tt = system_clock::to_time_t(now);
    struct tm curr;
    char timeStr[buffSize + 1] = {0};
    localtime_r(&tt, &curr);
    int32_t len = snprintf_s(timeStr, sizeof(timeStr), dataLen, "%04u-%02d-%02d %02d:%02d:%02d",
        curr.tm_year + startYear, curr.tm_mon + 1, curr.tm_mday, curr.tm_hour, curr.tm_min, curr.tm_sec);
    if (len < 0) {
        return std::string();
    }
    return std::string(timeStr);
}
} // namespace Common
} // namespace UserIam
} // namespace OHOS