/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef IAM_AUTH_WIDGET_HELPER_H
#define IAM_AUTH_WIDGET_HELPER_H

#include "context_factory.h"
#include "user_auth_common_defines.h"
#include "user_auth_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthWidgetHelper {
public:
    static bool InitWidgetContextParam(const AuthParamInner &authParam, std::vector<AuthType> &validType,
        const WidgetParam &widgetParam, ContextFactory::AuthWidgetContextPara &para);
    static int32_t CheckValidSolution(int32_t userId,
        const std::vector<AuthType> &authTypeList, const AuthTrustLevel &atl, std::vector<AuthType> &validTypeList);
    static int32_t CheckReuseUnlockResult(const ContextFactory::AuthWidgetContextPara &para,
        const AuthParamInner &authParam, Attributes &extraInfo);

private:
    static const uint32_t USER_AUTH_TOKEN_LEN = 148;

    static bool GetUserAuthProfile(int32_t userId, const AuthType &authType,
        ContextFactory::AuthWidgetContextPara::AuthProfile &profile);
    static bool ParseAttributes(const Attributes &values, const AuthType &authType,
        ContextFactory::AuthWidgetContextPara::AuthProfile &profile);
    static int32_t SetReuseUnlockResult(int32_t apiVersion, const HdiReuseUnlockInfo &info,
        Attributes &extraInfo);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_AUTH_WIDGET_HELPER_H