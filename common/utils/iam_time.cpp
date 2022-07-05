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

#include <chrono>
#include <securec.h>

#include "iam_time.h"

namespace OHOS {
namespace UserIAM {
namespace Common {
constexpr uint32_t BUFFSIZE = 64;
constexpr uint32_t DATALEN = 19;
constexpr uint32_t TMYEAR = 1900;
const std::string GetNowTimeString()
{
    using namespace std::chrono;
    const time_point<system_clock> now = system_clock::now();
    time_t tt = system_clock::to_time_t(now);
    struct tm curr;
    char timeStr[BUFFSIZE + 1] = {0};
    localtime_r(&tt, &curr);
    int error = snprintf_s(timeStr, sizeof(timeStr), DATALEN, "%04d-%02d-%02d %02d:%02d:%02d",
        curr.tm_year + TMYEAR, curr.tm_mon + 1, curr.tm_mday, curr.tm_hour, curr.tm_min, curr.tm_sec);
    if (error != EOK) {
        return std::string();
    }
    return std::string(timeStr);
}
} // namespace Common
} // namespace UserIAM
} // namespace OHOS