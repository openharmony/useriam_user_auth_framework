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

#include "user_idm_database_impl.h"

#include "securec.h"

#include "attributes.h"
#include "credential_info.h"
#include "credential_info_impl.h"
#include "enrolled_info_impl.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "iam_hitrace_helper.h"
#include "iam_common_defines.h"
#include "secure_user_info.h"
#include "secure_user_info_impl.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V1_0::EnrolledInfo;
using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;
using HdiCredentialInfo = OHOS::HDI::UserAuth::V1_0::CredentialInfo;
using HdiPinSubType = OHOS::HDI::UserAuth::V1_0::PinSubType;

std::shared_ptr<SecureUserInfo> UserIdmDatabaseImpl::GetSecUserInfo(int32_t userId)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return nullptr;
    }

    std::vector<HdiEnrolledInfo> enrolledInfoVector;
    uint64_t secureUid = 0;
    HdiPinSubType pinSubType;
    int32_t ret = hdi->GetUserInfo(userId, secureUid, pinSubType, enrolledInfoVector);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("GetSecureInfo failed, error code : %{public}d", ret);
        return nullptr;
    }

    std::vector<std::shared_ptr<EnrolledInfo>> infoRet;
    infoRet.reserve(enrolledInfoVector.size());

    for (auto const &info : enrolledInfoVector) {
        auto enrolledInfo = Common::MakeShared<EnrolledInfoImpl>(userId, info);
        if (enrolledInfo == nullptr) {
            IAM_LOGE("bad alloc");
            return nullptr;
        }
        infoRet.emplace_back(enrolledInfo);
    }
    auto secInfoRet = Common::MakeShared<SecureUserInfoImpl>(userId,
        static_cast<PinSubType>(pinSubType), secureUid, infoRet);
    if (secInfoRet == nullptr) {
        IAM_LOGE("bad alloc");
        return nullptr;
    }
    return secInfoRet;
}

std::vector<std::shared_ptr<CredentialInfo>> UserIdmDatabaseImpl::GetCredentialInfo(int32_t userId, AuthType authType)
{
    std::vector<std::shared_ptr<CredentialInfo>> infoRet;
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return infoRet;
    }

    std::vector<HdiCredentialInfo> hdiInfos;
    int32_t ret = hdi->GetCredential(userId, static_cast<HdiAuthType>(authType), hdiInfos);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("GetCredential failed, error code : %{public}d", ret);
        return infoRet;
    }
    infoRet.reserve(hdiInfos.size());
    for (const auto &hdiInfo : hdiInfos) {
        auto info = Common::MakeShared<CredentialInfoImpl>(userId, hdiInfo);
        if (info == nullptr) {
            IAM_LOGE("bad alloc");
            return infoRet;
        }
        infoRet.emplace_back(info);
    }

    return infoRet;
}

int32_t UserIdmDatabaseImpl::DeleteCredentialInfo(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t> &authToken, std::shared_ptr<CredentialInfo> &credInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return INVALID_HDI_INTERFACE;
    }

    HdiCredentialInfo hdiInfo = {};
    IamHitraceHelper traceHelper("hdi DeleteCredential");
    int32_t ret = hdi->DeleteCredential(userId, credentialId, authToken, hdiInfo);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("failed to delete credential, error code : %{public}d", ret);
        return ret;
    }

    auto info = Common::MakeShared<CredentialInfoImpl>(userId, hdiInfo);
    if (info == nullptr) {
        IAM_LOGE("bad alloc");
        return GENERAL_ERROR;
    }
    credInfo = info;
    return SUCCESS;
}

int32_t UserIdmDatabaseImpl::DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
    std::vector<std::shared_ptr<CredentialInfo>> &credInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return INVALID_HDI_INTERFACE;
    }

    std::vector<HdiCredentialInfo> hdiInfos;
    IamHitraceHelper traceHelper("hdi DeleteUser");
    int32_t ret = hdi->DeleteUser(userId, authToken, hdiInfos);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("failed to delete user, error code : %{public}d", ret);
        return ret;
    }

    for (auto info : hdiInfos) {
        auto infoRet = Common::MakeShared<CredentialInfoImpl>(userId, info);
        if (infoRet == nullptr) {
            IAM_LOGE("bad alloc");
            return GENERAL_ERROR;
        }
        credInfos.emplace_back(infoRet);
    }

    return SUCCESS;
}

int32_t UserIdmDatabaseImpl::DeleteUserEnforce(int32_t userId, std::vector<std::shared_ptr<CredentialInfo>> &credInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return INVALID_HDI_INTERFACE;
    }

    std::vector<HdiCredentialInfo> hdiInfos;
    IamHitraceHelper traceHelper("hdi EnforceDeleteUser");
    int32_t ret = hdi->EnforceDeleteUser(userId, hdiInfos);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("failed to enforce delete user, error code : %{public}d", ret);
        return ret;
    }

    for (auto info : hdiInfos) {
        auto infoRet = Common::MakeShared<CredentialInfoImpl>(userId, info);
        if (infoRet == nullptr) {
            IAM_LOGE("bad alloc");
            return GENERAL_ERROR;
        }
        credInfos.emplace_back(infoRet);
    }

    return SUCCESS;
}

UserIdmDatabase &UserIdmDatabase::Instance()
{
    return UserIdmDatabaseImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS