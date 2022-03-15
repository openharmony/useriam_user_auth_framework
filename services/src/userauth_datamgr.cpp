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
int32_t UserAuthDataMgr::AddContextID(uint64_t contextID)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth AddContextID is start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (contextIDs_.count(contextID) == 1) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth AddContextID error, because contextID is exist");
        return GENERAL_ERROR;
    }
    contextIDs_.insert(contextID);
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth AddContextID is end");
    return SUCCESS;
}
int32_t UserAuthDataMgr::IsContextIDExist(uint64_t contextID)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth IsContextIDExist is start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (contextIDs_.count(contextID) == 1) {
        return SUCCESS;
    }
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth IsContextIDExist is end");
    return GENERAL_ERROR;
}

int32_t UserAuthDataMgr::GenerateContextID(uint64_t &contextID)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GenerateContextID is start");

    std::lock_guard<std::mutex> lock(mutex_);
    do {
        if (RAND_bytes(reinterpret_cast<uint8_t *>(&contextID), (int)sizeof(contextID)) != OPENSSLSUCCESS) {
            USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth GenerateContextID Error");
            continue;
        }
    } while ((contextIDs_.count(contextID) > 0) || (contextID == 0));
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GenerateContextID is end");
    return SUCCESS;
}

int32_t UserAuthDataMgr::DeleteContextID(uint64_t contextID)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth DeleteContextID is start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (contextIDs_.count(contextID) == 0) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth ContextID invalid");
        return GENERAL_ERROR;
    }
    contextIDs_.erase(contextID);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
