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

#include "ipc_common.h"

#include "accesstoken_kit.h"
#include "result_code.h"
#include "iam_logger.h"
#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif // HAS_OS_ACCOUNT_PART
#define LOG_LABEL UserIAM::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t IpcCommon::GetCallingUserId(IPCObjectStub &stub, std::optional<int32_t> &userId)
{
    if (userId.has_value()) {
        return SUCCESS;
    }
    uint32_t tokenId = GetTokenId(stub);
    using namespace Security::AccessToken;
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType != TOKEN_HAP) {
        IAM_LOGE("failed to get calling type");
        return TYPE_NOT_SUPPORT;
    }
    HapTokenInfo hapTokenInfo;
    int result = AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get hap token info, result = %{public}d", result);
        return TYPE_NOT_SUPPORT;
    }
    userId = static_cast<int32_t>(hapTokenInfo.userID);
    IAM_LOGI("get callingUserId is %{public}d", userId.value());
    return SUCCESS;
}

int32_t IpcCommon::GetActiveAccountId(std::optional<int32_t> &userId)
{
    if (userId.has_value()) {
        return SUCCESS;
    }
    std::vector<int32_t> ids;
#ifdef HAS_OS_ACCOUNT_PART
    ErrCode queryRet = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (queryRet != ERR_OK || ids.empty()) {
        IAM_LOGE("failed to query active account id");
        return FAIL;
    }
#else  // HAS_OS_ACCOUNT_PART
    const int32_t DEFAULT_OS_ACCOUNT_ID = 0;
    ids.push_back(DEFAULT_OS_ACCOUNT_ID);
    IAM_LOGI("there is no os account part, use default id");
#endif // HAS_OS_ACCOUNT_PART
    userId = ids.front();
    return SUCCESS;
}

bool IpcCommon::CheckPermission(IPCObjectStub &stub, const std::string &permission)
{
    uint32_t tokenId = GetTokenId(stub);
    using namespace Security::AccessToken;
    return AccessTokenKit::VerifyAccessToken(tokenId, permission) == RET_SUCCESS;
}

uint32_t IpcCommon::GetTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetFirstTokenID();
    if (tokenId == 0) {
        tokenId = stub.GetCallingTokenID();
    }
    return tokenId;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS