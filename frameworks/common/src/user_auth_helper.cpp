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

#include "user_auth_helper.h"

#include <cinttypes>
 
#include "iam_logger.h"
 
#define LOG_TAG "USER_AUTH_COMMON"
 
namespace OHOS {
namespace UserIam {
namespace UserAuth {

int32_t UserAuthHelper::GetResultCodeV10(int32_t result)
{
    if (result == CHECK_PERMISSION_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED);
    }
    if (result == INVALID_PARAMETERS) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_INVALID_PARAM);
    }
    if (result == CHECK_SYSTEM_APP_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED);
    }
    if (result == HARDWARE_NOT_SUPPORTED) {
        return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
    }
    if (result > (INT32_MAX - static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MIN))) {
        return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
    }
    int32_t resultCodeV10 = result + static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MIN);
    if (resultCodeV10 >= static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MIN) &&
        resultCodeV10 <= static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MAX)) {
        IAM_LOGI("version GetResultCodeV10 resultCodeV10 result: %{public}d", resultCodeV10);
        return resultCodeV10;
    }
    IAM_LOGE("version GetResultCodeV10 resultCodeV10 error");
    return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
}
 
bool UserAuthHelper::CheckUserAuthType(int32_t authType)
{
    if (authType != AuthType::PIN && authType != AuthType::FACE &&
        authType != AuthType::FINGERPRINT && authType != AuthType::PRIVATE_PIN) {
        IAM_LOGE("authType check fail:%{public}d", authType);
        return false;
    }
    return true;
}
 
bool UserAuthHelper::CheckAuthTrustLevel(uint32_t authTrustLevel)
{
    if (authTrustLevel != AuthTrustLevel::ATL1 && authTrustLevel != AuthTrustLevel::ATL2 &&
        authTrustLevel != AuthTrustLevel::ATL3 && authTrustLevel != AuthTrustLevel::ATL4) {
        IAM_LOGE("authTrustLevel check fail:%{public}d", authTrustLevel);
        return false;
    }
    return true;
}
 
 bool UserAuthHelper::CheckReuseUnlockResult(ReuseUnlockResult reuseUnlockResult)
 {
    if (reuseUnlockResult.reuseMode != ReuseMode::AUTH_TYPE_RELEVANT &&
        reuseUnlockResult.reuseMode != ReuseMode::AUTH_TYPE_IRRELEVANT &&
        reuseUnlockResult.reuseMode != ReuseMode::CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT &&
        reuseUnlockResult.reuseMode != ReuseMode::CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT) {
        IAM_LOGE("reuseMode check fail:%{public}u", reuseUnlockResult.reuseMode);
        return false;
    }
    if (reuseUnlockResult.reuseDuration <= 0 || reuseUnlockResult.reuseDuration > MAX_ALLOWABLE_REUSE_DURATION) {
        IAM_LOGE("reuseDuration check fail:%{public}" PRIu64, reuseUnlockResult.reuseDuration);
        return false;
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
