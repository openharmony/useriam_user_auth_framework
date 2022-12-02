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

#include "mock_ipc_common.h"

#include "iam_common_defines.h"
#include "iam_logger.h"
#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif // HAS_OS_ACCOUNT_PART
#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace {
    const uint32_t TEST_USER_ID = 548781;
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::set<Permission> IpcCommon::permSet_;

int32_t IpcCommon::GetCallingUserId(IPCObjectStub &stub, int32_t &userId)
{
    if (userId != 0) {
        return SUCCESS;
    }
    userId = TEST_USER_ID;
    return SUCCESS;
}

int32_t IpcCommon::GetActiveUserId(std::optional<int32_t> &userId)
{
    if (userId.has_value() && userId.value() != 0) {
        return SUCCESS;
    }
    std::vector<int32_t> ids;
#ifdef HAS_OS_ACCOUNT_PART
    ErrCode queryRet = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (queryRet != ERR_OK || ids.empty()) {
        IAM_LOGE("failed to query active account id");
        return GENERAL_ERROR;
    }
#else  // HAS_OS_ACCOUNT_PART
    const int32_t DEFAULT_OS_ACCOUNT_ID = 0;
    ids.push_back(DEFAULT_OS_ACCOUNT_ID);
    IAM_LOGI("there is no os account part, use default id");
#endif // HAS_OS_ACCOUNT_PART
    userId = ids.front();
    return SUCCESS;
}

// for unittest only
bool IpcCommon::CheckPermission(IPCObjectStub &stub, Permission permission)
{
    return permSet_.find(permission) != permSet_.end();
}

uint32_t IpcCommon::GetAccessTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetFirstTokenID();
    if (tokenId == 0) {
        tokenId = stub.GetCallingTokenID();
    }
    return tokenId;
}

void IpcCommon::AddPermission(Permission perm)
{
    permSet_.insert(perm);
}

void IpcCommon::DeleteAllPermission()
{
    permSet_.clear();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS