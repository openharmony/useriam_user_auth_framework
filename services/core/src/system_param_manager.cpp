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

#include "system_param_manager.h"
#include "parameter.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr int SYSTEM_PARAM_VAL_LEN = 6;
SystemParamManager::SystemParamManager()
{
}

bool SystemParamManager::GetCredentialCheckedParam()
{
    char isCredentialCheckedChar[SYSTEM_PARAM_VAL_LEN] = { 0 };
    int32_t ret = GetParameter("useriam.isCredentialChecked", "", isCredentialCheckedChar, SYSTEM_PARAM_VAL_LEN);
    if (ret < 0) {
        IAM_LOGE("failed to get param %{public}s", "useriam.isCredentialChecked");
    }
    std::string isCredentialCheckedStr = isCredentialCheckedChar;
    if (isCredentialCheckedStr == "false") {
        return false;
    } else {
        return true;
    }
}

void SystemParamManager::SetPinEnrolledParam(bool pinEnrolled)
{
    IAM_LOGI("start");
    if (pinEnrolled) {
        SetParameter("persist.useriam.isPinEnrolled", "false");
        SetParameter("persist.useriam.isPinEnrolled", "true");
    } else {
        SetParameter("persist.useriam.isPinEnrolled", "false");
    }
    IAM_LOGI("set pin enrolled parameter success, %{public}d", pinEnrolled);
}

void SystemParamManager::SetCredentialCheckedParam(bool credentialChecked)
{
    if (credentialChecked) {
        SetParameter("useriam.isCredentialChecked", "false");
        SetParameter("useriam.isCredentialChecked", "true");
    } else {
        SetParameter("useriam.isCredentialChecked", "false");
    }
    IAM_LOGI("set credential checked parameter success, %{public}d", credentialChecked);
}

void SystemParamManager::SetStopParam(bool processStop)
{
    if (processStop) {
        SetParameter("useriam.stopSa", "false");
        SetParameter("useriam.stopSa", "true");
    } else {
        SetParameter("useriam.stopSa", "false");
    }
    IAM_LOGI("set process stop parameter success, %{public}d", processStop);
}

void SystemParamManager::SetFuncReadyParam(bool funcReady)
{
    IAM_LOGI("start");
    if (funcReady) {
        SetParameter("useriam.isPinFunctionReady", "false");
        SetParameter("useriam.isPinFunctionReady", "true");
    } else {
        SetParameter("useriam.isPinFunctionReady", "false");
    }
    IAM_LOGI("set func ready parameter success, %{public}d", funcReady);
}

SystemParamManager &SystemParamManager::GetInstance()
{
    static SystemParamManager systemParamManager;
    return systemParamManager;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS