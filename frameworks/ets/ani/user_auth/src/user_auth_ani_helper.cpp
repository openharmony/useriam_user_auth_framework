/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "user_auth_ani_helper.h"

#include <map>
#include <string>
#include <cinttypes>
#include "nlohmann/json.hpp"

#include "taihe/runtime.hpp"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_ANI"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

namespace {
const std::map<UserAuthResultCode, std::string> g_resultV92Str = {
    {UserAuthResultCode::OHOS_INVALID_PARAM, "Invalid authentication parameters."},
    {UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED, "Permission denied."},
    {UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED, "The caller is not a system application."},
    {UserAuthResultCode::SUCCESS, "Authentication succeeded."},
    {UserAuthResultCode::FAIL, "Authentication failed."},
    {UserAuthResultCode::GENERAL_ERROR, "Unknown errors."},
    {UserAuthResultCode::CANCELED, "Authentication canceled."},
    {UserAuthResultCode::TIMEOUT, "Authentication timeout."},
    {UserAuthResultCode::TYPE_NOT_SUPPORT, "Unsupport authentication type."},
    {UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT, "Unsupport authentication trust level."},
    {UserAuthResultCode::BUSY, "Authentication service is busy."},
    {UserAuthResultCode::LOCKED, "Authentication is lockout."},
    {UserAuthResultCode::NOT_ENROLLED, "Authentication template has not been enrolled."},
    {UserAuthResultCode::CANCELED_FROM_WIDGET, "Authentication is canceled from widget."},
    {UserAuthResultCode::PIN_EXPIRED, "Operation failed because of PIN expired."},
    {UserAuthResultCode::AUTH_TOKEN_CHECK_FAILED, "Operation failed because of authToken integrity check failed."},
    {UserAuthResultCode::AUTH_TOKEN_EXPIRED, "Operation failed because of authToken has expired."}
};

const std::string NOTICE_EVENT_TYPE = "event";
const std::string NOTICE_PAYLOAD = "payload";
const std::string NOTICE_PAYLOAD_TYPE = "type";
}  // namespace

bool UserAuthAniHelper::ConvertUserAuthType(int32_t userAuthType, userAuth::UserAuthType &userAuthTypeOut)
{
    switch (userAuthType) {
        case AuthType::PIN:
            userAuthTypeOut = userAuth::UserAuthType::key_t::PIN;
            return true;
        case AuthType::FACE:
            userAuthTypeOut = userAuth::UserAuthType::key_t::FACE;
            return true;
        case AuthType::FINGERPRINT:
            userAuthTypeOut = userAuth::UserAuthType::key_t::FINGERPRINT;
            return true;
        case AuthType::PRIVATE_PIN:
            userAuthTypeOut = userAuth::UserAuthType::key_t::PRIVATE_PIN;
            return true;
        default:
            IAM_LOGE("invalid userAuthType:%{public}d", userAuthType);
            return false;
    }
}

UserAuthResultCode UserAuthAniHelper::ThrowBusinessError(UserAuthResultCode error, std::string message)
{
    std::string msgStr;
    auto res = g_resultV92Str.find(error);
    if (res == g_resultV92Str.end()) {
        IAM_LOGE("result %{public}d not found", static_cast<int32_t>(error));
        error = UserAuthResultCode::GENERAL_ERROR;
    }
    msgStr = g_resultV92Str.at(error);
    IAM_LOGI("ThrowBusinessError, errorCode: %{public}d, errmsg: %{public}s", error, msgStr.c_str());
    taihe::set_business_error(static_cast<int32_t>(error), msgStr);
    return error;
}

bool UserAuthAniHelper::VerifyNoticeParam(const std::string &eventData)
{
    auto json = nlohmann::json::parse(eventData.c_str(), nullptr, false);
    if (json.is_null() || json.is_discarded()) {
        IAM_LOGE("Notice data is invalid json object");
        return false;
    }

    if (json.find(NOTICE_EVENT_TYPE) == json.end() || !json[NOTICE_EVENT_TYPE].is_string()) {
        IAM_LOGE("Invalid event type exist in notice data");
        return false;
    }

    if (json.find(NOTICE_PAYLOAD) == json.end() ||
        json[NOTICE_PAYLOAD].find(NOTICE_PAYLOAD_TYPE) == json[NOTICE_PAYLOAD].end() ||
        !json[NOTICE_PAYLOAD][NOTICE_PAYLOAD_TYPE].is_array()) {
        IAM_LOGE("Invalid payload exist in notice data");
        return false;
    }
    IAM_LOGI("valid notice parameter");
    return true;
}
}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS
 