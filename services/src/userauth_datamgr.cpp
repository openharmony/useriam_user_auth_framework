/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "userauth_common.h"

#include <openssl/bn.h>

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
    int32_t ret = SUCCESS;
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth AddContextID is start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (contextIDs_.count(contextID) == 1) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth AddContextID error, because contextID is exist");
        return GENERAL_ERROR;
    }
    contextIDs_.insert(contextID);

    return ret;
}
int32_t UserAuthDataMgr::IsContextIDExist(uint64_t contextID)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth IsContextIDExist is start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (contextIDs_.count(contextID) == 1) {
        return SUCCESS;
    }
    return GENERAL_ERROR;
}
int32_t UserAuthDataMgr::GenerateContextID(uint64_t &contextID)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GenerateContextID is start");
    BIGNUM *btmp = BN_new();
    if (btmp == nullptr) {
        return GENERAL_ERROR;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    do {
        if (!BN_rand(btmp, USERAUTH_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
            BN_free(btmp);
            USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth GenerateContextID fail");
            return GENERAL_ERROR;
        }
        char *tmprand = BN_bn2dec(btmp);
        contextID = std::atoll(tmprand);
    } while ((contextIDs_.count(contextID) == 1) || (contextID == 0));
    BN_free(btmp);

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
