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
#include <inttypes.h>

#include "userauth_adapter.h"
#include "userauth_hilog_wrapper.h"
#include "userauth_info.h"
#include "auth_attributes.h"
#include "co_auth.h"
#include "useridm_client.h"
#include "useridm_info.h"
#include "userauth_datamgr.h"
#include "userauth_excallback_impl.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
const int g_userAuthVersion = 1235;
UserAuthAdapter &UserAuthAdapter::GetInstance()
{
    static UserAuthAdapter instance;
    return instance;
}

int32_t UserAuthAdapter::GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t &authTrustLevel)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GetAuthTrustLevel is start!");
    int32_t ret = OHOS::UserIAM::UserAuth::GetAuthTrustLevel(userId, authType, authTrustLevel);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth GetAuthTrustLevel ERROR!");
    }

    return ret;
}

void UserAuthAdapter::GetPropAuthInfo(int32_t userID, uint64_t callerUID, std::string pkgName,
    GetPropertyRequest requset, sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GetPropAuthInfo is start!");
    using namespace UserIDM;
    std::shared_ptr<GetInfoCallback> getInfoCallback =
        std::make_shared<UserAuthCallbackImplIDMGetPorp>(callback, requset, callerUID, pkgName);
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(userID,
        static_cast<UserIDM::AuthType>(requset.authType), getInfoCallback);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth GetPropAuthInfo ERROR!");
    }
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GetPropAuthInfo is end!");
}

void UserAuthAdapter::SetPropAuthInfo(uint64_t callerUID, std::string pkgName, int32_t resultCode,
                                      UserAuthToken authToken, SetPropertyRequest requset,
                                      std::vector<uint64_t> templateIds,
                                      sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth SetPropAuthInfo is start!");
    using namespace AuthResPool;
    FreezInfo freezInfo;
    freezInfo.callerID = callerUID;
    freezInfo.authType = requset.authType;
    freezInfo.pkgName = pkgName;
    freezInfo.resultCode = resultCode;

    std::shared_ptr<CoAuth::SetPropCallback> setPropCallback =
        std::make_shared<UserAuthCallbackImplSetPropFreez>(callback, templateIds, authToken, freezInfo);
    AuthAttributes authAttributes;
    int32_t ret = SetProPropAuthInfo(authAttributes, callerUID, pkgName, requset, templateIds, setPropCallback);
    if (ret != SUCCESS) {
        return;
    }
    CoAuth::CoAuth::GetInstance().SetExecutorProp(authAttributes, setPropCallback);
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth SetPropAuthInfo is end!");
}
int32_t UserAuthAdapter::SetProPropAuthInfo(OHOS::UserIAM::AuthResPool::AuthAttributes &authAttributes,
                                            uint64_t callerUID, std::string pkgName,
                                            SetPropertyRequest requset, std::vector<uint64_t> templateIds,
                                            std::shared_ptr<CoAuth::SetPropCallback> &setPropCallback)
{
    uint32_t value;
    int32_t ret = authAttributes.SetUint32Value(AUTH_TYPE, requset.authType);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value AUTH_TYPE ERROR!");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    value = requset.key == SetPropertyType::FREEZE_TEMPLATE ?
        static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_FREEZE)
        : static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_UNFREEZE);
    ret = authAttributes.SetUint32Value(AUTH_PROPERTY_MODE, value);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value AUTH_PROPERTY_MODE ERROR!");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    ret = authAttributes.SetUint64Value(AUTH_CALLER_UID, callerUID);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value AUTH_CALLER_UID ERROR!");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    std::vector<uint8_t> pkgNameValue;
    pkgName.resize(pkgName.size());
    pkgNameValue.clear();
    pkgNameValue.assign(pkgName.begin(), pkgName.end());
    ret = authAttributes.SetUint8ArrayValue(AUTH_CALLER_NAME, pkgNameValue);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint8ArrayValue->AUTH_CALLER_NAME ERROR!");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    ret = authAttributes.SetUint64ArrayValue(AUTH_TEMPLATE_ID_LIST, templateIds);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint64ArrayValue AUTH_TEMPLATE_ID_LIST ERROR!");
        std::vector<uint8_t> extraInfo;
        setPropCallback->OnResult(ret, extraInfo);
        return ret;
    }
    return ret;
}
void UserAuthAdapter::GetPropAuthInfoCoauth(int32_t userID, uint64_t callerUID, std::string pkgName, int32_t resultCode,
                                            UserAuthToken authToken, GetPropertyRequest requset,
                                            sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GetPropAuthInfoCoauth is start!");
    using namespace UserIDM;
    std::shared_ptr<GetInfoCallback> getInfoCallback =
        std::make_shared<UserAuthCallbackImplIDMGetPorpCoauth>(callback, callerUID, pkgName, resultCode,
                                                               authToken, requset);
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(userID,
        static_cast<UserIDM::AuthType>(requset.authType), getInfoCallback);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth GetPropAuthInfoCoauth ERROR!");
    }
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GetPropAuthInfoCoauth is end!");
}

void UserAuthAdapter::CoauthSetPropAuthInfo(int32_t userID, int32_t resultCode, uint64_t callerUID, std::string pkgName,
                                            UserAuthToken authToken, SetPropertyRequest requset,
                                            sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth CoauthSetPropAuthInfo is start!");
    using namespace UserIDM;
    std::shared_ptr<GetInfoCallback> setPropCallback =
        std::make_shared<UserAuthCallbackImplIDMCothGetPorpFreez>(callback, callerUID, pkgName, resultCode,
                                                                  authToken, requset);
    int32_t ret = UserIDMClient::GetInstance().GetAuthInfo(userID,
        static_cast<UserIDM::AuthType>(requset.authType), setPropCallback);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth CoauthSetPropAuthInfo ERROR!");
    }
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth CoauthSetPropAuthInfo is end!");
}

int32_t UserAuthAdapter::GenerateSolution(AuthSolution param, std::vector<uint64_t> &sessionIds)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GenerateSolution is start!");
    int32_t ret = OHOS::UserIAM::UserAuth::GenerateSolution(param, sessionIds);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth GenerateSolution ERROR!");
    }
    return ret;
}

int32_t UserAuthAdapter::RequestAuthResult(uint64_t contextId, std::vector<uint8_t> scheduleToken,
                                           UserAuthToken &authToken, std::vector<uint64_t> &sessionIds)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth RequestAuthResult is start!");
    int32_t ret = OHOS::UserIAM::UserAuth::RequestAuthResult(contextId, scheduleToken, authToken, sessionIds);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth RequestAuthResult ERROR!");
    }
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth RequestAuthResult is end!");
    return ret;
}

int32_t UserAuthAdapter::CancelContext(uint64_t contextId, std::vector<uint64_t> &sessionIds)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth CancelContext is start!");
    int32_t ret = OHOS::UserIAM::UserAuth::CancelContext(contextId, sessionIds);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth CancelContext ERROR!");
    }
    return ret;
}

int32_t UserAuthAdapter::Cancel(uint64_t sessionId)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth Cancel is start!");
    int32_t ret = CoAuth::CoAuth::GetInstance().Cancel(sessionId);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth Cancel ERROR!");
    }
    return ret;
}

int32_t UserAuthAdapter::GetVersion()
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GetVersion is start!");
    int32_t version = g_userAuthVersion;

    return version;
}

int32_t UserAuthAdapter::GetExecutorProp(uint64_t callerUID, std::string pkgName, uint64_t templateId,
                                         GetPropertyRequest requset, ExecutorProperty &result)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth GetExecutorProp is start!");
    using namespace AuthResPool;
    uint32_t value;

    auto pAuthAttributes (std::make_shared<AuthAttributes>());
    AuthAttributes cAuthAttributes;
    int32_t ret = cAuthAttributes.SetUint32Value(AUTH_TYPE, requset.authType);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value AUTH_TYPE ERROR!");
        return ret;
    }
    ret = cAuthAttributes.SetUint32Value(AUTH_PROPERTY_MODE, PROPERMODE_GET);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value AUTH_PROPERTY_MODE ERROR!");
        result.result = ret;
        return ret;
    }
    ret = cAuthAttributes.SetUint64Value(AUTH_TEMPLATE_ID, templateId);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint64Value AUTH_TEMPLATE_ID ERROR!");
        result.result = ret;
        return ret;
    }
    ret = cAuthAttributes.SetUint64Value(AUTH_CALLER_UID, callerUID);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value AUTH_CALLER_UID ERROR!");
        return ret;
    }
    std::vector<uint8_t> pkgNameValue;
    pkgName.resize(pkgName.size());
    pkgNameValue.clear();
    pkgNameValue.assign(pkgName.begin(), pkgName.end());
    ret = cAuthAttributes.SetUint8ArrayValue(AUTH_CALLER_NAME, pkgNameValue);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint8ArrayValue->AUTH_CALLER_NAME ERROR!");
        result.result = ret;
        return ret;
    }
    ret = CoAuth::CoAuth::GetInstance().GetExecutorProp(cAuthAttributes, pAuthAttributes);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth CoAuth_->GetExecutorProp ERROR!");
        result.result = ret;
        return ret;
    }
    if (GetEachExecutorProp(requset, result, value, pAuthAttributes) != SUCCESS) {
        return ret;
    }
    result.result = SUCCESS;
    return ret;
}

int32_t UserAuthAdapter::GetEachExecutorProp(GetPropertyRequest &requset, ExecutorProperty &result, uint32_t &value,
    std::shared_ptr<OHOS::UserIAM::AuthResPool::AuthAttributes> pAuthAttributes)
{
    uint64_t tmpValue;
    int32_t ret = SUCCESS;

    result.freezingTime = 0;
    result.remainTimes = 0;
    result.authSubType = UserAuth::PIN_SIX;
    for (auto const &item : requset.keys) {
        switch (item) {
            case AUTH_SUB_TYPE:
                ret = pAuthAttributes->GetUint64Value(AUTH_SUBTYPE, tmpValue);
                if (ret != SUCCESS) {
                    USERAUTH_HILOGE(MODULE_SERVICE, "GetUint64Value->AUTH_SUBTYPE ERROR!");
                    result.result = ret;
                    return ret;
                }
                result.authSubType = static_cast<AuthSubType>(tmpValue);
                break;
            case REMAIN_TIMES:
                ret = pAuthAttributes->GetUint32Value(AUTH_REMAIN_COUNT, result.remainTimes);
                if (ret != SUCCESS) {
                    USERAUTH_HILOGE(MODULE_SERVICE, "GetUint32Value->AUTH_REMAIN_COUNT ERROR!");
                    result.result = ret;
                    return ret;
                }
                break;
            case FREEZING_TIME:
                ret = pAuthAttributes->GetUint32Value(AUTH_REMAIN_TIME, result.freezingTime);
                if (ret != SUCCESS) {
                    USERAUTH_HILOGE(MODULE_SERVICE, "GetUint32Value->AUTH_REMAIN_TIME ERROR!");
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
    USERAUTH_HILOGE(MODULE_SERVICE, "UserAuthAdapter::GetEachExecutorProp %{public}" PRIu64 ":%{public}u:%{public}u",
        result.authSubType, result.remainTimes, result.freezingTime);
    return ret;
}

int32_t UserAuthAdapter::SetExecutorProp(uint64_t callerUID, std::string pkgName, SetPropertyRequest requset,
                                         sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth SetExecutorProp is start!");
    using namespace AuthResPool;
    uint32_t value;

    std::shared_ptr<CoAuth::SetPropCallback> setPropCallback = std::make_shared<UserAuthCallbackImplSetProp>(callback);
    AuthAttributes pAuthAttributes;
    value = requset.key == SetPropertyType::INIT_ALGORITHM ?
        static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_INIT_ALGORITHM)
        : static_cast<uint32_t>(AuthPropertyMode::PROPERMODE_RELEASE_ALGORITHM);
    int32_t ret = pAuthAttributes.SetUint32Value(AUTH_PROPERTY_MODE, value);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value SET_AUTH_PROPERTY_MODE ERROR!");
        return ret;
    }
    ret = pAuthAttributes.SetUint64Value(AUTH_CALLER_UID, callerUID);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value AUTH_CALLER_UID ERROR!");
        return ret;
    }
    std::vector<uint8_t> pkgNameValue;
    pkgName.resize(pkgName.size());
    pkgNameValue.clear();
    pkgNameValue.assign(pkgName.begin(), pkgName.end());
    ret = pAuthAttributes.SetUint8ArrayValue(AUTH_CALLER_NAME, pkgNameValue);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint8ArrayValue->AUTH_CALLER_NAME ERROR!");
        return ret;
    }
    ret = pAuthAttributes.SetUint32Value(AUTH_TYPE, requset.authType);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint32Value AUTH_TYPE ERROR!");
        return ret;
    }
    ret = pAuthAttributes.SetUint8ArrayValue(ALGORITHM_INFO, requset.setInfo);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SetUint8ArrayValue init ERROR!");
        return ret;
    }
    CoAuth::CoAuth::GetInstance().SetExecutorProp(pAuthAttributes, setPropCallback);
    return ret;
}

int32_t UserAuthAdapter::coAuth(CoAuthInfo coAuthInfo, sptr<IUserAuthCallback>& callback)
{
    USERAUTH_HILOGD(MODULE_SERVICE, "UserAuth coAuth is start!");

    std::shared_ptr<CoAuth::CoAuthCallback> coAuthCallback =
        std::make_shared<UserAuthCallbackImplCoAuth>(callback, coAuthInfo, false);
    OHOS::UserIAM::CoAuth::AuthInfo authInfo;
    int32_t ret = authInfo.SetPkgName(coAuthInfo.pkgName);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth authInfo SetPkgName ERROR!");
        return ret;
    }
    ret = authInfo.SetCallerUid(coAuthInfo.callerID);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth authInfo SetCallerUid ERROR!");
        return ret;
    }

    ret = UserAuthCallbackImplCoAuth::SaveCoauthCallback(coAuthInfo.contextID, coAuthCallback);
    if (ret != SUCCESS) {
        USERAUTH_HILOGE(MODULE_SERVICE, "UserAuth SaveCoauthCallback ERROR!");
        return ret;
    }
    for (auto const &item : coAuthInfo.sessionIds) {
        CoAuth::CoAuth::GetInstance().BeginSchedule(item, authInfo, coAuthCallback);
    }

    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
