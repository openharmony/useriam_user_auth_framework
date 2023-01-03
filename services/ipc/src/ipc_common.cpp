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
#include "iam_common_defines.h"
#include "iam_logger.h"
#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif // HAS_OS_ACCOUNT_PART
#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace PermissionString {
    const std::string MANAGE_USER_IDM_PERMISSION = "ohos.permission.MANAGE_USER_IDM";
    const std::string USE_USER_IDM_PERMISSION = "ohos.permission.USE_USER_IDM";
    const std::string ACCESS_USER_AUTH_INTERNAL_PERMISSION = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
    const std::string ACCESS_BIOMETRIC_PERMISSION = "ohos.permission.ACCESS_BIOMETRIC";
    const std::string ACCESS_AUTH_RESPOOL = "ohos.permission.ACCESS_AUTH_RESPOOL";
    const std::string ENFORCE_USER_IDM = "ohos.permission.ENFORCE_USER_IDM";
}

namespace {
    // process white list of allowing to call, <processUid, processName>
    const std::vector<std::pair<int32_t, std::string>> whiteLists = {
        {3058, "accountmgr"},
    };
}

int32_t IpcCommon::GetCallingUserId(IPCObjectStub &stub, int32_t &userId)
{
    if (userId != 0) {
        return SUCCESS;
    }
    uint32_t tokenId = GetAccessTokenId(stub);
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
    IAM_LOGI("get callingUserId is %{public}d", userId);
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

bool IpcCommon::CheckPermission(IPCObjectStub &stub, Permission permission)
{
    switch (permission) {
        case MANAGE_USER_IDM_PERMISSION:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::MANAGE_USER_IDM_PERMISSION) &&
                CheckNativeCallingProcessWhiteList(stub);
        case USE_USER_IDM_PERMISSION:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::USE_USER_IDM_PERMISSION);
        case ACCESS_USER_AUTH_INTERNAL_PERMISSION:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        case ACCESS_BIOMETRIC_PERMISSION:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::ACCESS_BIOMETRIC_PERMISSION);
        case ACCESS_AUTH_RESPOOL:
            return CheckDirectCaller(stub, PermissionString::ACCESS_AUTH_RESPOOL);
        case ENFORCE_USER_IDM:
            return CheckDirectCaller(stub, PermissionString::ENFORCE_USER_IDM) &&
                CheckNativeCallingProcessWhiteList(stub);
        default:
            IAM_LOGE("failed to check permission");
            return false;
    }
}

uint32_t IpcCommon::GetAccessTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetFirstTokenID();
    if (tokenId == 0) {
        tokenId = stub.GetCallingTokenID();
    }
    return tokenId;
}

bool IpcCommon::CheckNativeCallingProcessWhiteList(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetCallingTokenID();
    using namespace Security::AccessToken;
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType != TOKEN_NATIVE) {
        IAM_LOGE("failed to get calling type");
        return false;
    }
    NativeTokenInfo nativeTokenInfo;
    int result = AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get native token info, result = %{public}d", result);
        return false;
    }

    std::string processName = nativeTokenInfo.processName;
    int32_t processUid = stub.GetCallingUid();
    for (const auto &whiteList : whiteLists) {
        if (whiteList.first == processUid && whiteList.second == processName) {
            return true;
        }
    }
    IAM_LOGE("failed to check process white list");
    return false;
}

bool IpcCommon::CheckDirectCallerAndFirstCallerIfSet(IPCObjectStub &stub, const std::string &permission)
{
    uint32_t firstTokenId = stub.GetFirstTokenID();
    uint32_t callingTokenId = stub.GetCallingTokenID();
    using namespace Security::AccessToken;
    if ((firstTokenId != 0 && AccessTokenKit::VerifyAccessToken(firstTokenId, permission) != RET_SUCCESS) ||
        AccessTokenKit::VerifyAccessToken(callingTokenId, permission) != RET_SUCCESS) {
        IAM_LOGE("failed to check permission");
        return false;
    }
    return true;
}

bool IpcCommon::CheckDirectCaller(IPCObjectStub &stub, const std::string &permission)
{
    uint32_t callingTokenId = stub.GetCallingTokenID();
    using namespace Security::AccessToken;
    if (AccessTokenKit::VerifyAccessToken(callingTokenId, permission) != RET_SUCCESS) {
        IAM_LOGE("failed to check permission");
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS