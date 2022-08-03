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

#include "auth_common.h"

#include "iam_logger.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
ExecuteInfo::ExecuteInfo(napi_env napiEnv) : env(napiEnv)
{
}

ExecuteInfo::~ExecuteInfo()
{
    if (env != nullptr && callbackRef != nullptr) {
        IAM_LOGI("ExecuteInfo::~ExecuteInfo delete callbackRef");
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
}

AuthInfo::AuthInfo(napi_env napiEnv) : env(napiEnv)
{
}

AuthInfo::~AuthInfo()
{
    if (env == nullptr) {
        return;
    }
    if (onResult != nullptr) {
        IAM_LOGI("AuthInfo::~AuthInfo delete onResult");
        napi_delete_reference(env, onResult);
        onResult = nullptr;
    }
    if (onAcquireInfo != nullptr) {
        IAM_LOGI("AuthInfo::~AuthInfo delete onAcquireInfo");
        napi_delete_reference(env, onAcquireInfo);
        onAcquireInfo = nullptr;
    }
}

AuthUserInfo::AuthUserInfo(napi_env napiEnv) : env(napiEnv)
{
}

AuthUserInfo::~AuthUserInfo()
{
    if (env == nullptr) {
        return;
    }
    if (onResult != nullptr) {
        IAM_LOGI("AuthUserInfo::~AuthUserInfo delete onResult");
        napi_delete_reference(env, onResult);
        onResult = nullptr;
    }
    if (onAcquireInfo != nullptr) {
        IAM_LOGI("AuthUserInfo::~AuthUserInfo delete onAcquireInfo");
        napi_delete_reference(env, onAcquireInfo);
        onAcquireInfo = nullptr;
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS