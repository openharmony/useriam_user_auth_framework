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

#include "userauth_adapter.h"
#include <cinttypes>
#include "securec.h"
#include "auth_attributes.h"
#include "userauth_datamgr.h"
#include "userauth_excallback_impl.h"
#include "userauth_hilog_wrapper.h"
#include "userauth_info.h"
#include "useridm_info.h"
#include "useridm_controller.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
const int g_userAuthVersion = 0;
namespace UserAuthHdi = OHOS::HDI::UserAuth::V1_0;
UserAuthAdapter &UserAuthAdapter::GetInstance()
{
    static UserAuthAdapter instance;
    return instance;
}

int32_t UserAuthAdapter::GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t &authTrustLevel)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "GetAuthTrustLevel start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    int32_t ret = hdiInterface->GetAuthTrustLevel(userId, static_cast<UserAuthHdi::AuthType>(authType), authTrustLevel);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GetAuthTrustLevel failed");
    }
    return ret;
}

void UserAuthAdapter::GetPropAuthInfo(int32_t userId, uint64_t callerUid, const std::string &pkgName,
    const GetPropertyRequest &request, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "GetPropAuthInfo start");
    using namespace UserIDM;
    std::shared_ptr<GetInfoCallback> getInfoCallback =
        std::make_shared<UserAuthCallbackImplIdmGetProp>(callback, request, callerUid, pkgName);
    std::vector<CredentialInfo> credInfos;
    int32_t ret = UserIDMController::GetInstance().GetAuthInfoCtrl(userId,
        static_cast<UserIDM::AuthType>(request.authType), credInfos);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GetAuthInfo failed");
    }
    USERAUTH_HILOGI(MODULE_SERVICE, "GetPropAuthInfo end");
    getInfoCallback->OnGetInfo(credInfos);
}

void UserAuthAdapter::SetPropAuthInfo(CallerInfo callerInfo, int32_t resultCode, std::vector<uint8_t> &authToken,
    SetPropertyRequest request, std::vector<uint64_t> templateIds)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "SetPropAuthInfo start");
    using namespace AuthResPool;
    FreezeInfo freezeInfo;
    freezeInfo.callerID = callerInfo.callerUID;
    freezeInfo.authType = request.authType;
    freezeInfo.pkgName = callerInfo.pkgName;
    freezeInfo.resultCode = resultCode;

    std::shared_ptr<CoAuth::SetPropCallback> setPropCallback =
        std::make_shared<UserAuthCallbackImplSetPropFreeze>(templateIds, authToken, freezeInfo);
    if (setPropCallback == nullptr) {
        USERAUTH_HILOGE(MODULE_SERVICE, "SetPropAuthInfo setPropCallback nullptr");
        return;
    }
    AuthAttributes authAttributes;
    int32_t ret = SetProPropAuthInfo(authAttributes, callerInfo, request, templateIds, setPropCallback);
    if (ret != SUCCESS) {
        return;
    }
    CoAuth::CoAuthManager::GetInstance().SetExecutorProp(authAttributes, setPropCallback);
    USERAUTH_HILOGI(MODULE_SERVICE, "SetPropAuthInfo end");
}

int32_t UserAuthAdapter::SetProPropAuthInfo(OHOS::UserIAM::AuthResPool::AuthAttributes &authAttributes,
    CallerInfo callerInfo, SetPropertyRequest request, std::vector<uint64_t> templateIds,
    std::shared_ptr<CoAuth::SetPropCallback> &setPropCallback)
{
    uint32_t value;
    int32_t ret = authAttributes.SetUint32Value(AUTH_TYPE, request.authType);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_TYPE failed");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    value = (request.key == SetPropertyType::FREEZE_TEMPLATE
                ? static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_FREEZE)
                : static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_UNFREEZE));
    ret = authAttributes.SetUint32Value(AUTH_PROPERTY_MODE, value);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_PROPERTY_MODE failed");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    ret = authAttributes.SetUint64Value(AUTH_CALLER_UID, callerInfo.callerUID);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_CALLER_UID failed");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    std::vector<uint8_t> pkgNameValue;
    callerInfo.pkgName.resize(callerInfo.pkgName.size());
    pkgNameValue.clear();
    pkgNameValue.assign(callerInfo.pkgName.begin(), callerInfo.pkgName.end());
    ret = authAttributes.SetUint8ArrayValue(AUTH_CALLER_NAME, pkgNameValue);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_CALLER_NAME failed");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    ret = authAttributes.SetUint64ArrayValue(AUTH_TEMPLATE_ID_LIST, templateIds);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_TEMPLATE_ID_LIST failed");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    return ret;
}

void UserAuthAdapter::GetPropAuthInfoCoAuth(CallerInfo callerInfo, int32_t resultCode, std::vector<uint8_t> &authToken,
    GetPropertyRequest request, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "GetPropAuthInfoCoAuth start");
    using namespace UserIDM;
    std::shared_ptr<GetInfoCallback> getInfoCallback = std::make_shared<UserAuthCallbackImplIdmGetPropCoAuth>(callback,
        callerInfo.callerUID, callerInfo.pkgName, resultCode, authToken, request);
    std::vector<CredentialInfo> credInfos;
    int32_t ret = UserIDMController::GetInstance().GetAuthInfoCtrl(callerInfo.userID,
        static_cast<UserIDM::AuthType>(request.authType), credInfos);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GetAuthInfo failed");
    }
    USERAUTH_HILOGI(MODULE_SERVICE, "GetPropAuthInfoCoAuth end");
    getInfoCallback->OnGetInfo(credInfos);
}

void UserAuthAdapter::CoAuthSetPropAuthInfo(CallerInfo callerInfo, int32_t resultCode, std::vector<uint8_t> &authToken,
    SetPropertyRequest request)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "CoAuthSetPropAuthInfo start");
    using namespace UserIDM;
    std::shared_ptr<GetInfoCallback> setPropCallback = std::make_shared<UserAuthCallbackImplIdmCoAuthGetPropFreeze>(
        callerInfo.callerUID, callerInfo.pkgName, resultCode, authToken, request);
    std::vector<CredentialInfo> credInfos;
    int32_t ret = UserIDMController::GetInstance().GetAuthInfoCtrl(callerInfo.userID,
        static_cast<UserIDM::AuthType>(request.authType), credInfos);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GetAuthInfo failed");
    }
    USERAUTH_HILOGI(MODULE_SERVICE, "CoAuthSetPropAuthInfo end");
    setPropCallback->OnGetInfo(credInfos);
}

bool UserAuthAdapter::CopyScheduleInfo(const UserAuthHdi::ScheduleInfo &in, CoAuth::ScheduleInfo &out)
{
    if (in.executors.size() == 0 || in.templateIds.size() == 0) {
        COAUTH_HILOGE(MODULE_SERVICE, "param is invalid");
        return false;
    }
    out.scheduleId = in.scheduleId;
    out.templateId = in.templateIds[0];
    out.authSubType = static_cast<uint64_t>(in.executorMatcher);
    out.scheduleMode = in.scheduleMode;
    for (auto &executor : in.executors) {
        auto &info = executor.info;
        if (info.publicKey.size() != CoAuth::PUBLIC_KEY_LEN) {
            COAUTH_HILOGE(MODULE_SERVICE, "publicKey is invalid");
            return false;
        }
        CoAuth::ExecutorInfo temp = {};
        temp.executorId = executor.executorIndex;
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

int32_t UserAuthAdapter::GenerateSolution(const AuthSolution &param, std::vector<CoAuth::ScheduleInfo> &scheduleInfos)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuth GenerateSolution start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    UserAuthHdi::AuthSolution hdiSolution = {};
    hdiSolution.userId = param.userId;
    hdiSolution.authTrustLevel = param.authTrustLevel;
    hdiSolution.authType = static_cast<UserAuthHdi::AuthType>(param.authType);
    hdiSolution.challenge.resize(sizeof(uint64_t));
    if (memcpy_s(&hdiSolution.challenge[0], hdiSolution.challenge.size(), &param.challenge, sizeof(uint64_t)) != EOK) {
        USERAUTH_HILOGE(MODULE_SERVICE, "copy challenge failed");
        return GENERAL_ERROR;
    }
    std::vector<UserAuthHdi::ScheduleInfo> hdiScheduleInfos;
    int32_t ret = hdiInterface->BeginAuthentication(param.contextId, hdiSolution, hdiScheduleInfos);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "BeginAuthentication failed");
        return ret;
    }
    std::vector<uint64_t> schedueIds;
    for (uint32_t i = 0; i < hdiScheduleInfos.size(); i++) {
        CoAuth::ScheduleInfo info;
        if (!CopyScheduleInfo(hdiScheduleInfos[i], info)) {
            USERAUTH_HILOGE(MODULE_SERVICE, "CopyScheduleInfo failed");
            return GENERAL_ERROR;
        }
        scheduleInfos.push_back(info);
        schedueIds.push_back(info.scheduleId);
    }
    ret = UserAuthDataMgr::GetInstance().SetScheduleIds(param.contextId, schedueIds);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "SetScheduleIds failed");
    }
    return ret;
}

int32_t UserAuthAdapter::RequestAuthResult(uint64_t contextId, std::vector<uint8_t> scheduleToken,
    std::vector<uint8_t> &authToken)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "RequestAuthResult start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    UserAuthHdi::AuthResultInfo resultInfo;
    int32_t ret = hdiInterface->UpdateAuthenticationResult(contextId, scheduleToken, resultInfo);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UpdateAuthenticationResult failed");
        return ret;
    }
    authToken = resultInfo.token;
    USERAUTH_HILOGI(MODULE_SERVICE, "RequestAuthResult end");
    return ret;
}

int32_t UserAuthAdapter::CancelContext(uint64_t contextId)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "CancelContext start");
    auto hdiInterface = UserAuthHdi::IUserAuthInterface::Get();
    if (hdiInterface == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "hdiInterface is nullptr!");
        return GENERAL_ERROR;
    }
    int32_t ret = hdiInterface->CancelAuthentication(contextId);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "CancelContext failed");
    }
    return ret;
}

int32_t UserAuthAdapter::Cancel(uint64_t sessionId)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "Cancel start");
    int32_t ret = CoAuth::CoAuthManager::GetInstance().Cancel(sessionId);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Cancel failed");
    }
    return ret;
}

int32_t UserAuthAdapter::GetVersion()
{
    USERAUTH_HILOGI(MODULE_SERVICE, "GetVersion start");
    int32_t version = g_userAuthVersion;

    return version;
}

int32_t UserAuthAdapter::GetExecutorProp(uint64_t callerUid, std::string pkgName, uint64_t templateId,
    GetPropertyRequest request, ExecutorProperty &result)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "GetExecutorProp start");
    using namespace AuthResPool;
    uint32_t value;

    auto pAuthAttributes(std::make_shared<AuthAttributes>());
    AuthAttributes cAuthAttributes;
    int32_t ret = cAuthAttributes.SetUint32Value(AUTH_TYPE, request.authType);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_TYPE failed");
        return ret;
    }
    ret = cAuthAttributes.SetUint32Value(AUTH_PROPERTY_MODE, PROPERMODE_GET);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_PROPERTY_MODE failed");
        result.result = ret;
        return ret;
    }
    ret = cAuthAttributes.SetUint64Value(AUTH_TEMPLATE_ID, templateId);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_TEMPLATE_ID failed");
        result.result = ret;
        return ret;
    }
    ret = cAuthAttributes.SetUint64Value(AUTH_CALLER_UID, callerUid);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_CALLER_UID failed");
        return ret;
    }
    std::vector<uint8_t> pkgNameValue;
    pkgName.resize(pkgName.size());
    pkgNameValue.clear();
    pkgNameValue.assign(pkgName.begin(), pkgName.end());
    ret = cAuthAttributes.SetUint8ArrayValue(AUTH_CALLER_NAME, pkgNameValue);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_CALLER_NAME failed");
        result.result = ret;
        return ret;
    }
    ret = CoAuth::CoAuthManager::GetInstance().GetExecutorProp(cAuthAttributes, pAuthAttributes);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "GetExecutorProp failed");
        result.result = ret;
        return ret;
    }
    if (GetEachExecutorProp(request, result, value, pAuthAttributes) != SUCCESS) {
        return ret;
    }
    result.result = SUCCESS;
    return ret;
}

int32_t UserAuthAdapter::GetEachExecutorProp(GetPropertyRequest &request, ExecutorProperty &result, uint32_t &value,
    std::shared_ptr<OHOS::UserIAM::AuthResPool::AuthAttributes> pAuthAttributes)
{
    uint64_t tmpValue;
    int32_t ret = SUCCESS;

    result.freezingTime = 0;
    result.remainTimes = 0;
    result.authSubType = UserAuth::PIN_SIX;
    for (auto const &item : request.keys) {
        switch (item) {
            case AUTH_SUB_TYPE:
                ret = pAuthAttributes->GetUint64Value(AUTH_SUBTYPE, tmpValue);
                if (ret != SUCCESS) {
                    USERAUTH_HILOGE(MODULE_SERVICE, "Get AUTH_SUBTYPE failed");
                    result.result = ret;
                    return ret;
                }
                result.authSubType = static_cast<AuthSubType>(tmpValue);
                break;
            case REMAIN_TIMES:
                ret = pAuthAttributes->GetUint32Value(AUTH_REMAIN_COUNT, result.remainTimes);
                if (ret != SUCCESS) {
                    USERAUTH_HILOGE(MODULE_SERVICE, "Get AUTH_REMAIN_COUNT failed");
                    result.result = ret;
                    return ret;
                }
                break;
            case FREEZING_TIME:
                ret = pAuthAttributes->GetUint32Value(AUTH_REMAIN_TIME, result.freezingTime);
                if (ret != SUCCESS) {
                    USERAUTH_HILOGE(MODULE_SERVICE, "Get AUTH_REMAIN_TIME failed");
                    result.result = ret;
                    return ret;
                }
                break;
            default:
                USERAUTH_HILOGE(MODULE_SERVICE, "The key to get ExecutorProp is invalid.");
                result.result = INVALID_PARAMETERS;
                return INVALID_PARAMETERS;
        }
    }
    USERAUTH_HILOGI(MODULE_SERVICE, "UserAuthAdapter::GetEachExecutorProp %{public}" PRIu64 ":%{public}u:%{public}u",
        result.authSubType, result.remainTimes, result.freezingTime);
    return ret;
}

int32_t UserAuthAdapter::SetExecutorProp(uint64_t callerUid, std::string pkgName, SetPropertyRequest request,
    sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "SetExecutorProp start");
    using namespace AuthResPool;
    uint32_t value;

    std::shared_ptr<CoAuth::SetPropCallback> setPropCallback = std::make_shared<UserAuthCallbackImplSetProp>(callback);
    AuthAttributes authAttributes;
    value = (request.key == SetPropertyType::INIT_ALGORITHM
                ? static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_INIT_ALGORITHM)
                : static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_RELEASE_ALGORITHM));
    int32_t ret = authAttributes.SetUint32Value(AUTH_PROPERTY_MODE, value);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set SET_AUTH_PROPERTY_MODE failed");
        return ret;
    }
    ret = authAttributes.SetUint64Value(AUTH_CALLER_UID, callerUid);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_CALLER_UID failed");
        return ret;
    }
    std::vector<uint8_t> pkgNameValue;
    pkgName.resize(pkgName.size());
    pkgNameValue.clear();
    pkgNameValue.assign(pkgName.begin(), pkgName.end());
    ret = authAttributes.SetUint8ArrayValue(AUTH_CALLER_NAME, pkgNameValue);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_CALLER_NAME failed");
        return ret;
    }
    ret = authAttributes.SetUint32Value(AUTH_TYPE, request.authType);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set AUTH_TYPE failed");
        return ret;
    }
    ret = authAttributes.SetUint8ArrayValue(ALGORITHM_INFO, request.setInfo);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "Set ALGORITHM_INFO failed");
        return ret;
    }
    CoAuth::CoAuthManager::GetInstance().SetExecutorProp(authAttributes, setPropCallback);
    return ret;
}

int32_t UserAuthAdapter::CoAuth(const std::vector<CoAuth::ScheduleInfo> &scheduleInfos,
    CoAuthInfo coAuthInfo, sptr<IUserAuthCallback> &callback)
{
    USERAUTH_HILOGI(MODULE_SERVICE, "CoAuth start");

    std::shared_ptr<CoAuth::CoAuthCallback> coAuthCallback =
        std::make_shared<UserAuthCallbackImplCoAuth>(callback, coAuthInfo, false);
    OHOS::UserIAM::CoAuth::AuthInfo authInfo;
    int32_t ret = authInfo.SetPkgName(coAuthInfo.pkgName);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "SetPkgName failed");
        return ret;
    }
    ret = authInfo.SetCallerUid(coAuthInfo.callerID);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "SetCallerUid failed");
        return ret;
    }

    ret = UserAuthCallbackImplCoAuth::SaveCoAuthCallback(coAuthInfo.contextID, coAuthCallback);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "SaveCoAuthCallback failed");
        return ret;
    }
    for (auto &scheduleInfo : scheduleInfos) {
        CoAuth::CoAuthManager::GetInstance().BeginSchedule(scheduleInfo, authInfo, coAuthCallback);
    }

    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
