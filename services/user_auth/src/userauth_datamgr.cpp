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

#include "userauth_datamgr.h"
#include <openssl/rand.h>
#include "userauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
UserAuthDataMgr &UserAuthDataMgr::GetInstance()
{
    static UserAuthDataMgr instance;
    return instance;
}

bool UserAuthDataMgr::IsContextIdExist(uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthDataMgr IsContextIdExist start");
    auto iter = contexts_.find(contextId);
    return (iter != contexts_.end());
}

int32_t UserAuthDataMgr::AddContextId(uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthDataMgr AddContextId start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (IsContextIdExist(contextId)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "contextId is exist");
        return GENERAL_ERROR;
    }
    contexts_[contextId] = {};
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthDataMgr AddContextId end");
    return SUCCESS;
}

int32_t UserAuthDataMgr::GenerateContextId(uint64_t &contextId)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthDataMgr GenerateContextId start");

    std::lock_guard<std::mutex> lock(mutex_);
    do {
        if (RAND_bytes(reinterpret_cast<uint8_t *>(&contextId), (int)sizeof(contextId)) != OPENSSLSUCCESS) {
            USERAUTH_HILOGE(MODULE_SERVICE, "GenerateContextId failed");
            continue;
        }
    } while (IsContextIdExist(contextId) || (contextId == 0));
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthDataMgr GenerateContextId end");
    return SUCCESS;
}

int32_t UserAuthDataMgr::DeleteContextId(uint64_t contextId)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthDataMgr DeleteContextId start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsContextIdExist(contextId)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "contextId invalid");
        return GENERAL_ERROR;
    }
    contexts_.erase(contextId);
    return SUCCESS;
}

int32_t UserAuthDataMgr::SetScheduleIds(uint64_t contextId, const std::vector<uint64_t> &sheduleIds)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthDataMgr SetScheduleIds start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsContextIdExist(contextId)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "contextId invalid");
        return GENERAL_ERROR;
    }
    contexts_[contextId] = sheduleIds;
    return SUCCESS;
}

int32_t UserAuthDataMgr::GetScheduleIds(uint64_t contextId, std::vector<uint64_t> &sheduleIds)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuthDataMgr GetScheduleIds start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsContextIdExist(contextId)) {
        USERAUTH_HILOGE(MODULE_SERVICE, "contextId invalid");
        return GENERAL_ERROR;
    }
    sheduleIds = contexts_[contextId];
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
