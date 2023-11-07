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

#ifndef IAM_AUTH_WIDGET_HELPER_H
#define IAM_AUTH_WIDGET_HELPER_H

#include "context_factory.h"
#include "user_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class AuthWidgetHelper {
public:
    static bool InitWidgetContextParam(
        int32_t userId, const AuthParam &authParam, std::vector<AuthType> &validType,
        const WidgetParam &widgetParam, ContextFactory::AuthWidgetContextPara &para);
    static int32_t CheckValidSolution(int32_t userId,
        const std::vector<AuthType> &authTypeList, const AuthTrustLevel &atl, std::vector<AuthType> &validTypeList);

private:
    static bool GetUserAuthProfile(int32_t userId, const AuthType &authType,
        ContextFactory::AuthWidgetContextPara::AuthProfile &profile);
    static bool ParseAttributes(const Attributes &values, const AuthType &authType,
        ContextFactory::AuthWidgetContextPara::AuthProfile &profile);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_AUTH_WIDGET_HELPER_H