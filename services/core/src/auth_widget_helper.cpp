/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "auth_widget_helper.h"

#include "iam_logger.h"
#include "resource_node_pool.h"
#include "user_idm_database.h"
#include "widget_client.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_SA

namespace OHOS {
namespace UserIam {
namespace UserAuth {

bool AuthWidgetHelper::InitWidgetContextParam(int32_t userId, const AuthParam &authParam,
    const WidgetParam &widgetParam, ContextFactory::AuthWidgetContextPara &para)
{
    for (auto &authType : authParam.authType) {
        ContextFactory::AuthWidgetContextPara::AuthProfile profile;
        if (!GetUserAuthProfile(userId, authType, profile, para.callingUid)) {
            IAM_LOGE("get user auth profile failed");
            return false;
        } else {
            para.authProfileMap[authType] = profile;
            if (authType == AuthType::PIN) {
                WidgetClient::Instance().SetPinSubType(static_cast<PinSubType>(profile.pinSubType));
            } else if (authType == AuthType::FINGERPRINT) {
                WidgetClient::Instance().SetSensorInfo(profile.sensorInfo);
            } else if (authType == AuthType::ALL) {
                WidgetClient::Instance().SetPinSubType(static_cast<PinSubType>(profile.pinSubType));
                WidgetClient::Instance().SetSensorInfo(profile.sensorInfo);
            }
        }
    }
    para.challenge = std::move(authParam.challenge);
    para.authTypeList = authParam.authType;
    para.atl = authParam.authTrustLevel;
    para.widgetParam = widgetParam;
    if (para.widgetParam.windowMode == WindowModeType::UNKNOWN_WINDOW_MODE) {
        para.widgetParam.windowMode = WindowModeType::DIALOG_BOX;
    }
    return true;
}

bool AuthWidgetHelper::GetUserAuthProfile(int32_t userId, const AuthType &authType,
    ContextFactory::AuthWidgetContextPara::AuthProfile &profile, uint32_t callingUid)
{
    Attributes values;
    auto credentialInfos = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType);
    if (credentialInfos.empty() || credentialInfos[0] == nullptr) {
        IAM_LOGE("user %{public}d has no credential type %{public}d", userId, authType);
        return false;
    }
    uint64_t executorIndex = credentialInfos[0]->GetExecutorIndex();
    auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        return false;
    }

    std::vector<uint64_t> templateIds;
    templateIds.reserve(credentialInfos.size());
    for (auto &info : credentialInfos) {
        templateIds.push_back(info->GetTemplateId());
    }
    std::vector<uint32_t> uint32Keys = {
        Attributes::ATTR_SENSOR_INFO,
        Attributes::ATTR_REMAIN_TIMES,
        Attributes::ATTR_FREEZING_TIME
    };
    if (authType == AuthType::PIN) {
        uint32Keys.push_back(Attributes::ATTR_PIN_SUB_TYPE);
    }

    Attributes attr;
    attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);
    attr.SetUint64Value(Attributes::ATTR_CALLER_UID, static_cast<uint64_t>(callingUid));
    attr.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, uint32Keys);
    int32_t result = resourceNode->GetProperty(attr, values);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get property, result = %{public}d", result);
        return false;
    }
    return ParseAttributes(values, authType, profile);
}

bool AuthWidgetHelper::ParseAttributes(const Attributes &values, const AuthType &authType,
    ContextFactory::AuthWidgetContextPara::AuthProfile &profile)
{
    if (authType == AuthType::PIN) {
        if (!values.GetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, profile.pinSubType)) {
            IAM_LOGE("get ATTR_PIN_SUB_TYPE failed");
            return false;
        }
    }
    if (!values.GetStringValue(Attributes::ATTR_SENSOR_INFO, profile.sensorInfo)) {
        IAM_LOGE("get ATTR_SENSOR_INFO failed");
        return false;
    }
    if (!values.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, profile.remainTimes)) {
        IAM_LOGE("get ATTR_REMAIN_TIMES failed");
        return false;
    }
    if (!values.GetInt32Value(Attributes::ATTR_FREEZING_TIME, profile.freezingTime)) {
        IAM_LOGE("get ATTR_FREEZING_TIME failed");
        return false;
    }
    return true;
}

int32_t AuthWidgetHelper::CheckValidSolution(int32_t userId,
    const std::vector<AuthType> &authTypeList, const AuthTrustLevel &atl)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    IAM_LOGE("hdi interface authTypeList start");
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }
    std::vector<HdiAuthType> inputAuthType, validTypes;
    uint32_t inputAtl = atl;
    IAM_LOGE("hdi interface authTypeList size is:%{public}zu", authTypeList.size());
    for (size_t index = 0; index < authTypeList.size(); index++) {
        inputAuthType.emplace_back(static_cast<HdiAuthType>(authTypeList[index]));
        IAM_LOGE("hdi interface authTypeList now index is:%zu{public}", index);
    }
    int32_t result = hdi->GetValidSolution(userId, inputAuthType,
        inputAtl, validTypes);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get current supported authTrustLevel from hdi result:%{public}d userId:%{public}d",
            result, userId);
    }
    return result;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS