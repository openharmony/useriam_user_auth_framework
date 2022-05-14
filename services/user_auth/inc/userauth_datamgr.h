/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef USERAUTH_DATAMGR_H
#define USERAUTH_DATAMGR_H

#include <mutex>
#include <set>
#include "nocopyable.h"
#include "iuserauth_callback.h"
#include "userauth_adapter.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
constexpr int32_t OPENSSLSUCCESS = 1;
class UserAuthDataMgr {
public:
    DISALLOW_COPY_AND_MOVE(UserAuthDataMgr);
    static UserAuthDataMgr &GetInstance();
    int32_t AddContextId(uint64_t contextId);
    bool IsContextIdExist(uint64_t contextId);
    int32_t GenerateContextId(uint64_t &contextId);
    int32_t DeleteContextId(uint64_t contextId);
    int32_t SetScheduleIds(uint64_t contextId, const std::vector<uint64_t> &sheduleIds);
    int32_t GetScheduleIds(uint64_t contextId, std::vector<uint64_t> &sheduleIds);

private:
    UserAuthDataMgr() = default;
    ~UserAuthDataMgr() = default;
    std::mutex mutex_;
    std::map<uint64_t, std::vector<uint64_t>> contexts_;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // USERAUTH_DATAMGR_H
