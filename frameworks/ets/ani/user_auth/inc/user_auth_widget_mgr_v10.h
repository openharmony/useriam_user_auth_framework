/**
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

#ifndef USER_AUTH_WIDGET_MGR_V10
#define USER_AUTH_WIDGET_MGR_V10

#include <mutex>

#include "nocopyable.h"

#include "iam_common_defines.h"
#include "auth_common.h"
#include "user_auth_ani_helper.h"
#include "user_auth_client.h"
#include "user_auth_common_defines.h"
#include "user_auth_widget_callback_v10.h"

namespace userAuth = ohos::userIAM::userAuth::userAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class UserAuthWidgetMgr : public NoCopyable {
public:
    explicit UserAuthWidgetMgr();
    ~UserAuthWidgetMgr() = default;

    UserAuthResultCode Init(int32_t version);
    UserAuthResultCode OnCommand(userAuth::IAuthWidgetCallback const &callback);
    UserAuthResultCode OffCommand(taihe::optional_view<userAuth::IAuthWidgetCallback> callback);

private:
    int32_t version_ = 1;
    std::shared_ptr<UserAuthWidgetCallback> callback_ = nullptr;
};
}  // namespace UserAuth
}  // namespace UserIam
}  // namespace OHOS

#endif  // USER_AUTH_WIDGET_MGR_V10
