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

#include "useridm_adapter.h"
#include "securec.h"
#include "useridm_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
namespace UserAuthHdi = OHOS::HDI::UserAuth::V1_0;
UserIDMAdapter &UserIDMAdapter::GetInstance()
{
    static UserIDMAdapter instance;
    return instance;
}

void UserIDMAdapter::OpenEditSession(int32_t userId, uint64_t& challenge)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter OpenEditSession start");
    challenge = 0;
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return;
    }
    std::vector<uint8_t> hdiChallenge;
    int32_t ret = hdiInterface->OpenSession(userId, hdiChallenge);
    if (ret != SUCCESS || hdiChallenge.size() != sizeof(uint64_t)) {
        USERIDM_HILOGE(MODULE_SERVICE, "OpenSession failed: %{public}d", ret);
        return;
    }
    if (memcpy_s(&challenge, sizeof(uint64_t), &hdiChallenge[0], hdiChallenge.size()) != EOK) {
        USERIDM_HILOGE(MODULE_SERVICE, "copy challenge failed");
        return;
    }
}

void UserIDMAdapter::CloseEditSession()
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter CloseEditSession start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return;
    }
    int32_t ret = hdiInterface->CloseSession(0);
    USERIDM_HILOGD(MODULE_SERVICE, "call hdi info: CloseSession: %{public}d", ret);
}

int32_t UserIDMAdapter::CloseEditSession(int32_t userId)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter CloseEditSession start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return FAIL;
    }
    int32_t ret = hdiInterface->CloseSession(userId);
    USERIDM_HILOGD(MODULE_SERVICE, "call hdi info: CloseSession: %{public}d", ret);
    return ret;
}

void UserIDMAdapter::CopyCredentialFromHdi(const UserAuthHdi::CredentialInfo& in, UserIDM::CredentialInfo& out)
{
    out.authSubType = PIN_SIX;
    out.authType = OHOS::UserIAM::UserIDM::AuthType(in.authType);
    out.credentialId = in.credentialId;
    out.templateId = in.templateId;
}

int32_t UserIDMAdapter::QueryCredential(int32_t userId, AuthType authType,
    std::vector<OHOS::UserIAM::UserIDM::CredentialInfo>& credInfos)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter QueryCredential start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    std::vector<UserAuthHdi::CredentialInfo> hdiInfos;
    int32_t ret = hdiInterface->GetCredential(userId, static_cast<UserAuthHdi::AuthType>(authType), hdiInfos);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info error: %{public}d", ret);
        return ret;
    }

    size_t vectorSize = hdiInfos.size();
    if (vectorSize <= 0) {
        USERIDM_HILOGE(MODULE_SERVICE, "vector size is: %{public}zu", vectorSize);
        return GENERAL_ERROR;
    }
    for (auto &hdiInfo : hdiInfos) {
        OHOS::UserIAM::UserIDM::CredentialInfo credInfo = {};
        CopyCredentialFromHdi(hdiInfo, credInfo);
        credInfos.push_back(credInfo);
    }
    return ret;
}

int32_t UserIDMAdapter::GetSecureUid(int32_t userId, uint64_t& secureUid,
    std::vector<OHOS::UserIAM::UserIDM::EnrolledInfo>& enrolledInfos)
{
    USERIDM_HILOGI(MODULE_SERVICE, "UserIDMAdapter GetSecureUid start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    std::vector<UserAuthHdi::EnrolledInfo> hdiInfos;
    UserAuthHdi::PinSubType subType;
    int32_t ret = hdiInterface->GetUserInfo(userId, secureUid, subType, hdiInfos);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info: GetUserInfo: %{public}d", ret);
        return ret;
    }
    size_t vectorSize = hdiInfos.size();
    if (vectorSize <= 0) {
        USERIDM_HILOGE(MODULE_SERVICE, "vector size is: %{public}zu", vectorSize);
        return GENERAL_ERROR;
    }
    for (auto &hdiInfo : hdiInfos) {
        OHOS::UserIAM::UserIDM::EnrolledInfo enrollInfo = {};
        enrollInfo.authType = OHOS::UserIAM::UserIDM::AuthType(hdiInfo.authType);
        enrollInfo.enrolledId = hdiInfo.enrolledId;
        enrolledInfos.push_back(enrollInfo);
    }
    return ret;
}

bool UserIDMAdapter::CopyScheduleInfo(const UserAuthHdi::ScheduleInfo& in, CoAuth::ScheduleInfo& out)
{
    if (in.executors.size() == 0) {
        COAUTH_HILOGE(MODULE_SERVICE, "param is invalid");
        return false;
    }
    out.scheduleId = in.scheduleId;
    out.authSubType = static_cast<uint64_t>(in.executorMatcher);
    out.scheduleMode = in.scheduleMode;
    for (auto &executor : in.executors) {
        if (executor.info.publicKey.size() != CoAuth::PUBLIC_KEY_LEN) {
            COAUTH_HILOGE(MODULE_SERVICE, "publicKey is invalid");
            return false;
        }
        CoAuth::ExecutorInfo temp = {};
        temp.executorId = executor.executorIndex;
        auto &info = executor.info;
        temp.authType = static_cast<uint32_t>(info.authType);
        temp.authAbility = static_cast<uint64_t>(info.executorMatcher);
        temp.esl = static_cast<uint32_t>(info.esl);
        temp.executorType =  static_cast<uint32_t>(info.executorRole);
        if (memcpy_s(temp.publicKey, CoAuth::PUBLIC_KEY_LEN, &info.publicKey[0], info.publicKey.size()) != EOK) {
            COAUTH_HILOGE(MODULE_SERVICE, "copy publicKey failed");
            return false;
        }
        out.executors.push_back(temp);
    }
    return true;
}

int32_t UserIDMAdapter::InitSchedule(std::vector<uint8_t> autoToken, int32_t userId, AuthType authType,
    AuthSubType authSubType, CoAuth::ScheduleInfo& info)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter InitSchedule start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    UserAuthHdi::EnrollParam param = {};
    param.authType = static_cast<UserAuthHdi::AuthType>(authType);
    param.executorSensorHint = 0;
    UserAuthHdi::ScheduleInfo hdiInfo;
    int32_t ret = hdiInterface->BeginEnrollment(userId, autoToken, param, hdiInfo);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info error: %{public}d", ret);
        return ret;
    }
    if (!CopyScheduleInfo(hdiInfo, info)) {
        USERIDM_HILOGE(MODULE_SERVICE, "CopyScheduleInfo failed");
        return GENERAL_ERROR;
    }
    return ret;
}

int32_t UserIDMAdapter::Cancel(int32_t userId)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter Cancel start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    int32_t ret = hdiInterface->CancelEnrollment(userId);
    USERIDM_HILOGD(MODULE_SERVICE, "call hdi info: CancelEnrollment: %{public}d", ret);
    return ret;
}

int32_t UserIDMAdapter::DeleteCredential(int32_t userId, uint64_t credentialId, const std::vector<uint8_t>& authToken,
    OHOS::UserIAM::UserIDM::CredentialInfo& credInfo)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter DeleteCredential start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    UserAuthHdi::CredentialInfo hdiInfo = {};
    int32_t ret = hdiInterface->DeleteCredential(userId, credentialId, authToken, hdiInfo);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info error: %{public}d", ret);
        return ret;
    }
    CopyCredentialFromHdi(hdiInfo, credInfo);

    return ret;
}

int32_t UserIDMAdapter::DeleteUser(int32_t userId, const std::vector<uint8_t>& authToken,
    std::vector<OHOS::UserIAM::UserIDM::CredentialInfo>& credInfos)
{
    USERIDM_HILOGI(MODULE_SERVICE, "UserIDMAdapter DeleteUser start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    std::vector<UserAuthHdi::CredentialInfo> hdiInfos;
    int32_t ret = hdiInterface->DeleteUser(userId, authToken, hdiInfos);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info error: %{public}d", ret);
        return ret;
    }
    for (auto &hdiInfo : hdiInfos) {
        OHOS::UserIAM::UserIDM::CredentialInfo credInfo;
        CopyCredentialFromHdi(hdiInfo, credInfo);
        credInfos.push_back(credInfo);
    }
    return ret;
}

int32_t UserIDMAdapter::DeleteUserEnforce(int32_t userId,
    std::vector<OHOS::UserIAM::UserIDM::CredentialInfo>& credInfos)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter DeleteUserEnforce start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    std::vector<UserAuthHdi::CredentialInfo> hdiInfos;
    int32_t ret = hdiInterface->EnforceDeleteUser(userId, hdiInfos);
    if (ret != SUCCESS) {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info error: %{public}d", ret);
        return ret;
    }
    for (auto &hdiInfo : hdiInfos) {
        OHOS::UserIAM::UserIDM::CredentialInfo credInfo;
        CopyCredentialFromHdi(hdiInfo, credInfo);
        credInfos.push_back(credInfo);
    }
    return ret;
}

int32_t UserIDMAdapter::AddCredential(std::vector<uint8_t>& enrollToken, uint64_t& credentialId)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter AddCredential start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    UserAuthHdi::CredentialInfo hdiInfo;
    int32_t ret = hdiInterface->UpdateEnrollmentResult(0, enrollToken, credentialId, hdiInfo);
    USERIDM_HILOGI(MODULE_SERVICE, "call driver info: AddCredential: %{public}d", ret);

    return ret;
}

int32_t UserIDMAdapter::UpdateCredential(std::vector<uint8_t> enrollToken, uint64_t &credentialId,
    CredentialInfo &deletedCredential)
{
    USERIDM_HILOGD(MODULE_SERVICE, "UserIDMAdapter UpdateCredential start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        USERIDM_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    UserAuthHdi::CredentialInfo hdiInfo;
    int32_t ret = hdiInterface->UpdateEnrollmentResult(0, enrollToken, credentialId, hdiInfo);
    if (ret == SUCCESS) {
        CopyCredentialFromHdi(hdiInfo, deletedCredential);
    } else {
        USERIDM_HILOGE(MODULE_SERVICE, "call driver info: UpdateEnrollmentResult: %{public}d", ret);
    }

    return ret;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS